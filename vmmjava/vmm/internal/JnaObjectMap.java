package vmm.internal;

import java.lang.ref.WeakReference;
import java.util.*;

public class JnaObjectMap {
    private int counter = 1;
    private static JnaObjectMap instance;
    private final Map<Integer, WeakReference<Object>> map = new HashMap<>();

    public static synchronized JnaObjectMap getInstance() {
        if (instance == null) {
            instance = new JnaObjectMap();
        }
        return instance;
    }

    public synchronized Integer put(Object obj) {
        Integer key = Integer.valueOf(counter++);
        map.put(key, new WeakReference<>(obj));
        return key;
    }

    public synchronized Object get(Integer key) {
        WeakReference<Object> ref = map.get(key);
        if (ref != null) {
            return ref.get();
        }
        return null;
    }

    public synchronized void remove(Integer key) {
        map.remove(key);
    }
}