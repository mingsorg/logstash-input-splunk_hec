# Exercise the actual QueueWriter implementations passed to Java Input.start.
# Run inside each pinned Logstash distribution, never against mocks/old parent jars.
require 'java'
require 'json'
require 'tmpdir'
Dir['/usr/share/logstash/logstash-core/lib/jars/*.jar'].sort.each { |j| require j }
java_import org.logstash.RubyUtil
java_import org.logstash.Event
java_import org.logstash.ackedqueue.SettingsImpl
java_import org.logstash.ackedqueue.ext.JRubyAckedQueueExt
java_import org.logstash.ext.JrubyMemoryWriteClientExt
java_import org.logstash.ext.JrubyAckedWriteClientExt
java_import java.util.concurrent.ArrayBlockingQueue
java_import java.util.concurrent.atomic.AtomicInteger
java_import java.util.concurrent.atomic.AtomicReference
java_import java.lang.Thread

def exercise(name, writer, release)
  accepted = AtomicInteger.new
  error = AtomicReference.new
  worker = Thread.new do
    begin
      1000.times do
        event = java.util.HashMap.new
        event.put('event', 'x' * 4096)
        # Ruby's push alias accepts RubyEvent; invoke the Java Input Map overload.
        writer.to_java(org.logstash.execution.queue.QueueWriter).push(event)
        accepted.incrementAndGet
      end
    rescue Exception => e
      error.set(e.class.name + ': ' + e.message.to_s)
    end
  end
  worker.setDaemon(true)
  worker.start
  # Confirm a stable blocked producer, with finite deadlines in the driver too.
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
  before = nil
  while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    candidate = accepted.get
    sleep 0.25
    if worker.isAlive && accepted.get == candidate && %w[WAITING TIMED_WAITING].include?(worker.getState.to_s)
      before = candidate
      break
    end
    break unless worker.isAlive
  end
  raise "#{name}: did not reach a blocked producer: accepted=#{accepted.get}, error=#{error.get}" if before.nil?
  state = worker.getState.to_s
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  worker.interrupt
  # The approved/default input shutdown grace is ten seconds, not two.
  worker.join(10_000)
  stopped = !worker.isAlive
  after = accepted.get
  release.call
  worker.join(2000)
  sleep 0.1
  result = {queue: name, blocked_state: state, accepted_before_interrupt: before,
            accepted_after_interrupt: after, interrupt_stopped: stopped,
            alive_after_release: worker.isAlive, accepted_after_release: accepted.get,
            elapsed_ms: ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round,
            error: error.get}
  puts JSON.generate(result)
  raise "#{name}: cancellation is not bounded" unless stopped && !worker.isAlive && after == accepted.get
end

memory = ArrayBlockingQueue.new(1)
exercise('memory', JrubyMemoryWriteClientExt.create(memory), -> { memory.clear })
Dir.mktmpdir('hec-queue-probe') do |dir|
  settings = SettingsImpl.fileSettingsBuilder(dir).elementClass(Event.java_class)
    .capacity(65536).queueMaxBytes(131072).maxUnread(1)
    .checkpointMaxAcks(1).checkpointMaxWrites(1).build
  pq = JRubyAckedQueueExt.create(settings).to_java(JRubyAckedQueueExt)
  pq.open
  begin
    exercise('persisted', JrubyAckedWriteClientExt.create(pq), -> { pq.close })
  ensure
    pq.close rescue nil
  end
end
