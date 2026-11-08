package org.logstashplugins.hec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.*;

/** Persistent suffixes: staging never mutates or copies an accepted prefix. */
final class AssemblyChunks {
    static final class Text {
        final Text previous;
        final String suffix;
        final int length;
        @JsonCreator(mode=JsonCreator.Mode.DELEGATING)
        Text(String value){this(null,value);}
        Text(Text previous,String suffix){this.previous=previous;this.suffix=suffix;length=Math.addExact(previous==null?0:previous.length,suffix.length());}
        int length(){return length;}
        String since(Text ancestor){
            var parts=new ArrayDeque<String>();Text cursor=this;
            while(cursor!=ancestor){if(cursor==null)throw new IllegalArgumentException("not a text ancestor");parts.push(cursor.suffix);cursor=cursor.previous;}
            return String.join("",parts);
        }
        @JsonValue public String value(){return since(null);}
    }
    static final class Contributions extends AbstractList<Object> {
        final Contributions previous;
        final List<Object> suffix;
        final int count;
        @JsonCreator(mode=JsonCreator.Mode.DELEGATING)
        Contributions(List<Object> values){this(null,List.copyOf(values));}
        Contributions(Contributions previous,List<Object> suffix){this.previous=previous;this.suffix=List.copyOf(suffix);count=Math.addExact(previous==null?0:previous.count,suffix.size());}
        List<Object> since(Contributions ancestor){
            var parts=new ArrayDeque<List<Object>>();Contributions cursor=this;
            while(cursor!=ancestor){if(cursor==null)throw new IllegalArgumentException("not a contribution ancestor");parts.push(cursor.suffix);cursor=cursor.previous;}
            var result=new ArrayList<Object>();for(var part:parts)result.addAll(part);return result;
        }
        @Override public int size(){return count;}
        @Override public Object get(int index){
            Objects.checkIndex(index,count);Contributions cursor=this;
            while(cursor.previous!=null&&index<cursor.previous.count)cursor=cursor.previous;
            return cursor.suffix.get(index-(cursor.previous==null?0:cursor.previous.count));
        }
        @Override public Iterator<Object> iterator(){return since(null).iterator();}
    }
    private AssemblyChunks(){}
}
