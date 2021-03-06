/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.common.extension;

import org.apache.dubbo.common.URL;
import org.apache.dubbo.common.context.Lifecycle;
import org.apache.dubbo.common.extension.support.ActivateComparator;
import org.apache.dubbo.common.extension.support.WrapperComparator;
import org.apache.dubbo.common.lang.Prioritized;
import org.apache.dubbo.common.logger.Logger;
import org.apache.dubbo.common.logger.LoggerFactory;
import org.apache.dubbo.common.utils.ArrayUtils;
import org.apache.dubbo.common.utils.ClassUtils;
import org.apache.dubbo.common.utils.CollectionUtils;
import org.apache.dubbo.common.utils.ConcurrentHashSet;
import org.apache.dubbo.common.utils.ConfigUtils;
import org.apache.dubbo.common.utils.Holder;
import org.apache.dubbo.common.utils.ReflectUtils;
import org.apache.dubbo.common.utils.StringUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

import static java.util.Arrays.asList;
import static java.util.Collections.sort;
import static java.util.ServiceLoader.load;
import static java.util.stream.StreamSupport.stream;
import static org.apache.dubbo.common.constants.CommonConstants.COMMA_SPLIT_PATTERN;
import static org.apache.dubbo.common.constants.CommonConstants.DEFAULT_KEY;
import static org.apache.dubbo.common.constants.CommonConstants.REMOVE_VALUE_PREFIX;

/**
 * {@link org.apache.dubbo.rpc.model.ApplicationModel}, {@code DubboBootstrap} and this class are at
 * present designed to be singleton or static (by itself totally static or uses some static fields).
 * So the instances returned from them are of process or classloader scope. If you want to support
 * multiple dubbo servers in a single process, you may need to refactor these three classes.
 *
 * <p>Load dubbo extensions
 *
 * <ul>
 *   <li>auto inject dependency extension
 *   <li>auto wrap extension in wrapper
 *   <li>default extension is an adaptive instance
 * </ul>
 *
 * @see <a href="http://java.sun.com/j2se/1.5.0/docs/guide/jar/jar.html#Service%20Provider">Service
 *     Provider in Java 5</a>
 * @see org.apache.dubbo.common.extension.SPI
 * @see org.apache.dubbo.common.extension.Adaptive
 * @see org.apache.dubbo.common.extension.Activate
 */
public class ExtensionLoader<T> {

  private static final Logger logger = LoggerFactory.getLogger(ExtensionLoader.class);

  private static final Pattern NAME_SEPARATOR = Pattern.compile("\\s*[,]+\\s*");

  private static final ConcurrentMap<Class<?>, ExtensionLoader<?>> EXTENSION_LOADERS =
      new ConcurrentHashMap<>(64);

  private static final ConcurrentMap<Class<?>, Object> EXTENSION_INSTANCES =
      new ConcurrentHashMap<>(64);

  // 在获取一个ExtensionLoader的时候，会设置该字段的值，该字段的值即为 ExtensionLoader.getExtensionLoader(SpiService.class)
  // 中的SpiService.class的值
  private final Class<?> type;

  private final ExtensionFactory objectFactory;

  private final ConcurrentMap<Class<?>, String> cachedNames = new ConcurrentHashMap<>();

  private final Holder<Map<String, Class<?>>> cachedClasses = new Holder<>();

  private final Map<String, Object> cachedActivates = new ConcurrentHashMap<>();
  private final ConcurrentMap<String, Holder<Object>> cachedInstances = new ConcurrentHashMap<>();
  private final Holder<Object> cachedAdaptiveInstance = new Holder<>();
  private volatile Class<?> cachedAdaptiveClass = null;
  private String cachedDefaultName;
  private volatile Throwable createAdaptiveInstanceError;

  private Set<Class<?>> cachedWrapperClasses;

  private Map<String, IllegalStateException> exceptions = new ConcurrentHashMap<>();

  private static volatile LoadingStrategy[] strategies = loadLoadingStrategies();

  public static void setLoadingStrategies(LoadingStrategy... strategies) {
    if (ArrayUtils.isNotEmpty(strategies)) {
      ExtensionLoader.strategies = strategies;
    }
  }

  /**
   * Load all {@link Prioritized prioritized} {@link LoadingStrategy Loading Strategies} via {@link
   * ServiceLoader} 使用Java的SPI去加载需要加载的Dubbo的配置目录路径
   *
   * @return non-null
   * @since 2.7.7
   */
  private static LoadingStrategy[] loadLoadingStrategies() {
    return stream(load(LoadingStrategy.class).spliterator(), false)
        .sorted()
        .toArray(LoadingStrategy[]::new);
  }

  /**
   * Get all {@link LoadingStrategy Loading Strategies}
   *
   * @return non-null
   * @see LoadingStrategy
   * @see Prioritized
   * @since 2.7.7
   */
  public static List<LoadingStrategy> getLoadingStrategies() {
    return asList(strategies);
  }

  private ExtensionLoader(Class<?> type) {
    this.type = type;
    objectFactory =
        (type == ExtensionFactory.class
            ? null
            : ExtensionLoader.getExtensionLoader(ExtensionFactory.class).getAdaptiveExtension());
  }

  private static <T> boolean withExtensionAnnotation(Class<T> type) {
    return type.isAnnotationPresent(SPI.class);
  }

  @SuppressWarnings("unchecked")
  public static <T> ExtensionLoader<T> getExtensionLoader(Class<T> type) {
    if (type == null) {
      throw new IllegalArgumentException("Extension type == null");
    }
    if (!type.isInterface()) {
      throw new IllegalArgumentException("Extension type (" + type + ") is not an interface!");
    }
    if (!withExtensionAnnotation(type)) {
      throw new IllegalArgumentException(
          "Extension type ("
              + type
              + ") is not an extension, because it is NOT annotated with @"
              + SPI.class.getSimpleName()
              + "!");
    }

    ExtensionLoader<T> loader = (ExtensionLoader<T>) EXTENSION_LOADERS.get(type);
    if (loader == null) {
      EXTENSION_LOADERS.putIfAbsent(type, new ExtensionLoader<T>(type));
      loader = (ExtensionLoader<T>) EXTENSION_LOADERS.get(type);
    }
    return loader;
  }

  // For testing purposes only
  public static void resetExtensionLoader(Class type) {
    ExtensionLoader loader = EXTENSION_LOADERS.get(type);
    if (loader != null) {
      // Remove all instances associated with this loader as well
      Map<String, Class<?>> classes = loader.getExtensionClasses();
      for (Map.Entry<String, Class<?>> entry : classes.entrySet()) {
        EXTENSION_INSTANCES.remove(entry.getValue());
      }
      classes.clear();
      EXTENSION_LOADERS.remove(type);
    }
  }

  public static void destroyAll() {
    EXTENSION_INSTANCES.forEach(
        (_type, instance) -> {
          if (instance instanceof Lifecycle) {
            Lifecycle lifecycle = (Lifecycle) instance;
            try {
              lifecycle.destroy();
            } catch (Exception e) {
              logger.error("Error destroying extension " + lifecycle, e);
            }
          }
        });
  }

  private static ClassLoader findClassLoader() {
    return ClassUtils.getClassLoader(ExtensionLoader.class);
  }

  public String getExtensionName(T extensionInstance) {
    return getExtensionName(extensionInstance.getClass());
  }

  public String getExtensionName(Class<?> extensionClass) {
    getExtensionClasses(); // load class
    return cachedNames.get(extensionClass);
  }

  /**
   * This is equivalent to {@code getActivateExtension(url, key, null)}
   *
   * @param url url
   * @param key url parameter key which used to get extension point names
   * @return extension list which are activated.
   * @see #getActivateExtension(org.apache.dubbo.common.URL, String, String)
   */
  public List<T> getActivateExtension(URL url, String key) {
    return getActivateExtension(url, key, null);
  }

  /**
   * This is equivalent to {@code getActivateExtension(url, values, null)}
   *
   * @param url url
   * @param values extension point names
   * @return extension list which are activated
   * @see #getActivateExtension(org.apache.dubbo.common.URL, String[], String)
   */
  public List<T> getActivateExtension(URL url, String[] values) {
    return getActivateExtension(url, values, null);
  }

  /**
   * This is equivalent to {@code getActivateExtension(url, url.getParameter(key).split(","), null)}
   *
   * @param url url
   * @param key url parameter key which used to get extension point names
   * @param group group
   * @return extension list which are activated.
   * @see #getActivateExtension(org.apache.dubbo.common.URL, String[], String)
   */
  public List<T> getActivateExtension(URL url, String key, String group) {
    String value = url.getParameter(key);
    return getActivateExtension(
        url, StringUtils.isEmpty(value) ? null : COMMA_SPLIT_PATTERN.split(value), group);
  }

  /**
   * Get activate extensions.
   *
   * @param url url
   * @param values extension point names。通过URL的key获取到的激活点的名字
   * @param group group
   * @return extension list which are activated
   * @see org.apache.dubbo.common.extension.Activate
   */
  public List<T> getActivateExtension(URL url, String[] values, String group) {
    List<T> activateExtensions = new ArrayList<>();
    List<String> names = values == null ? new ArrayList<>(0) : asList(values);
    // 如果扩展点的名称包括了"-default",则所有的扩展点都不激活
    if (!names.contains(REMOVE_VALUE_PREFIX + DEFAULT_KEY)) {
      // 去加载所有的扩展点
      getExtensionClasses();
      // 在加载扩展点信息的时候，就会去加载他的自动激活的扩展点
      for (Map.Entry<String, Object> entry : cachedActivates.entrySet()) {
        String name = entry.getKey();
        Object activate = entry.getValue();

        String[] activateGroup, activateValue;

        // 如果有Activity注解，则获取他的group属性和value属性的值。下面是做兼容
        if (activate instanceof Activate) {
          activateGroup = ((Activate) activate).group();
          activateValue = ((Activate) activate).value();
        } else if (activate instanceof com.alibaba.dubbo.common.extension.Activate) {
          activateGroup = ((com.alibaba.dubbo.common.extension.Activate) activate).group();
          activateValue = ((com.alibaba.dubbo.common.extension.Activate) activate).value();
        } else {
          continue;
        }
        // names是需要激活的信息，name是目前拿到的激活点的名字。如果他们相等，则说明该激活点可以激活
        if (isMatchGroup(group, activateGroup)
            && !names.contains(name)
            && !names.contains(REMOVE_VALUE_PREFIX + name)
            && isActive(activateValue, url)) {
          activateExtensions.add(getExtension(name));
        }
      }
      activateExtensions.sort(ActivateComparator.COMPARATOR);
    }
    List<T> loadedExtensions = new ArrayList<>();
    for (int i = 0; i < names.size(); i++) {
      String name = names.get(i);
      // 如果名字不是以"-"开头，则激活该扩展点
      if (!name.startsWith(REMOVE_VALUE_PREFIX) && !names.contains(REMOVE_VALUE_PREFIX + name)) {
        // 如果他的名字是default，则激活所有的扩展点
        if (DEFAULT_KEY.equals(name)) {
          if (!loadedExtensions.isEmpty()) {
            activateExtensions.addAll(0, loadedExtensions);
            loadedExtensions.clear();
          }
        } else {
          loadedExtensions.add(getExtension(name));
        }
      }
    }
    // 如果加载的扩展点不为空，则激活所有的扩展点
    if (!loadedExtensions.isEmpty()) {
      activateExtensions.addAll(loadedExtensions);
    }
    // 激活的扩展点
    return activateExtensions;
  }

  private boolean isMatchGroup(String group, String[] groups) {
    if (StringUtils.isEmpty(group)) {
      return true;
    }
    if (groups != null && groups.length > 0) {
      for (String g : groups) {
        if (group.equals(g)) {
          return true;
        }
      }
    }
    return false;
  }

  private boolean isActive(String[] keys, URL url) {
    if (keys.length == 0) {
      return true;
    }
    for (String key : keys) {
      // @Active(value="key1:value1, key2:value2")
      String keyValue = null;
      if (key.contains(":")) {
        String[] arr = key.split(":");
        key = arr[0];
        keyValue = arr[1];
      }

      for (Map.Entry<String, String> entry : url.getParameters().entrySet()) {
        String k = entry.getKey();
        String v = entry.getValue();
        // key是需要相等
        // 如果keyValue不等于null,则他们的value值需要相等
        // 如果keyValue等于bull，则存在即可
        // 激活指定的key，如果配置的方式是key:value的形式，则key/value必须完全一直，否则只需要一个key即可
        if ((k.equals(key) || k.endsWith("." + key))
            && ((keyValue != null && keyValue.equals(v))
                || (keyValue == null && ConfigUtils.isNotEmpty(v)))) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Get extension's instance. Return <code>null</code> if extension is not found or is not
   * initialized. Pls. note that this method will not trigger extension load.
   *
   * <p>In order to trigger extension load, call {@link #getExtension(String)} instead.
   *
   * @see #getExtension(String)
   */
  @SuppressWarnings("unchecked")
  public T getLoadedExtension(String name) {
    if (StringUtils.isEmpty(name)) {
      throw new IllegalArgumentException("Extension name == null");
    }
    Holder<Object> holder = getOrCreateHolder(name);
    return (T) holder.get();
  }

  private Holder<Object> getOrCreateHolder(String name) {
    Holder<Object> holder = cachedInstances.get(name);
    if (holder == null) {
      cachedInstances.putIfAbsent(name, new Holder<>());
      holder = cachedInstances.get(name);
    }
    return holder;
  }

  /**
   * Return the list of extensions which are already loaded.
   *
   * <p>Usually {@link #getSupportedExtensions()} should be called in order to get all extensions.
   *
   * @see #getSupportedExtensions()
   */
  public Set<String> getLoadedExtensions() {
    return Collections.unmodifiableSet(new TreeSet<>(cachedInstances.keySet()));
  }

  public List<T> getLoadedExtensionInstances() {
    List<T> instances = new ArrayList<>();
    cachedInstances.values().forEach(holder -> instances.add((T) holder.get()));
    return instances;
  }

  public Object getLoadedAdaptiveExtensionInstances() {
    return cachedAdaptiveInstance.get();
  }

  //    public T getPrioritizedExtensionInstance() {
  //        Set<String> supported = getSupportedExtensions();
  //
  //        Set<T> instances = new HashSet<>();
  //        Set<T> prioritized = new HashSet<>();
  //        for (String s : supported) {
  //
  //        }
  //
  //    }

  /**
   * Find the extension with the given name. If the specified name is not found, then {@link
   * IllegalStateException} will be thrown.
   * 获取普通的扩展类。如果没有则回去创建一个扩展类。创建的时候，会缓存扩展类Class、扩展类实例、WrapperClass等信息。如果创建失败则会抛出异常。如果扩展类的名字为true，则会加载一个默认扩展类
   */
  @SuppressWarnings("unchecked")
  public T getExtension(String name) {
    return getExtension(name, true);
  }

  public T getExtension(String name, boolean wrap) {
    if (StringUtils.isEmpty(name)) {
      throw new IllegalArgumentException("Extension name == null");
    }
    // 如果传入的参数是true,则加载并饭会默认扩展类
    if ("true".equals(name)) {
      return getDefaultExtension();
    }
    // 先去获取一个Holder（持有该扩展点的缓存的实例），如果没有，则创建一个Holder
    final Holder<Object> holder = getOrCreateHolder(name);
    Object instance = holder.get();
    // 如果Holder中不存在实例，则创建一个实例
    if (instance == null) {
      // 加锁去实例化该对象
      synchronized (holder) {
        // 多线程下，如果被其他线程实例化了就不管了
        instance = holder.get();
        if (instance == null) {
          // 创建扩展点实例
          instance = createExtension(name, wrap);
          holder.set(instance);
        }
      }
    }
    return (T) instance;
  }

  /**
   * Get the extension by specified name if found, or {@link #getDefaultExtension() returns the
   * default one}
   *
   * @param name the name of extension
   * @return non-null
   */
  public T getOrDefaultExtension(String name) {
    return containsExtension(name) ? getExtension(name) : getDefaultExtension();
  }

  /** Return default extension, return <code>null</code> if it's not configured. */
  public T getDefaultExtension() {
    getExtensionClasses();
    if (StringUtils.isBlank(cachedDefaultName) || "true".equals(cachedDefaultName)) {
      return null;
    }
    return getExtension(cachedDefaultName);
  }

  public boolean hasExtension(String name) {
    if (StringUtils.isEmpty(name)) {
      throw new IllegalArgumentException("Extension name == null");
    }
    Class<?> c = this.getExtensionClass(name);
    return c != null;
  }

  public Set<String> getSupportedExtensions() {
    Map<String, Class<?>> clazzes = getExtensionClasses();
    return Collections.unmodifiableSet(new TreeSet<>(clazzes.keySet()));
  }

  public Set<T> getSupportedExtensionInstances() {
    List<T> instances = new LinkedList<>();
    Set<String> supportedExtensions = getSupportedExtensions();
    if (CollectionUtils.isNotEmpty(supportedExtensions)) {
      for (String name : supportedExtensions) {
        instances.add(getExtension(name));
      }
    }
    // sort the Prioritized instances
    sort(instances, Prioritized.COMPARATOR);
    return new LinkedHashSet<>(instances);
  }

  /** Return default extension name, return <code>null</code> if not configured. */
  public String getDefaultExtensionName() {
    getExtensionClasses();
    return cachedDefaultName;
  }

  /**
   * Register new extension via API
   *
   * @param name extension name
   * @param clazz extension class
   * @throws IllegalStateException when extension with the same name has already been registered.
   */
  public void addExtension(String name, Class<?> clazz) {
    getExtensionClasses(); // load classes

    if (!type.isAssignableFrom(clazz)) {
      throw new IllegalStateException(
          "Input type " + clazz + " doesn't implement the Extension " + type);
    }
    if (clazz.isInterface()) {
      throw new IllegalStateException("Input type " + clazz + " can't be interface!");
    }

    if (!clazz.isAnnotationPresent(Adaptive.class)) {
      if (StringUtils.isBlank(name)) {
        throw new IllegalStateException("Extension name is blank (Extension " + type + ")!");
      }
      if (cachedClasses.get().containsKey(name)) {
        throw new IllegalStateException(
            "Extension name " + name + " already exists (Extension " + type + ")!");
      }

      cachedNames.put(clazz, name);
      cachedClasses.get().put(name, clazz);
    } else {
      if (cachedAdaptiveClass != null) {
        throw new IllegalStateException(
            "Adaptive Extension already exists (Extension " + type + ")!");
      }

      cachedAdaptiveClass = clazz;
    }
  }

  /**
   * Replace the existing extension via API
   *
   * @param name extension name
   * @param clazz extension class
   * @throws IllegalStateException when extension to be placed doesn't exist
   * @deprecated not recommended any longer, and use only when test
   */
  @Deprecated
  public void replaceExtension(String name, Class<?> clazz) {
    getExtensionClasses(); // load classes

    if (!type.isAssignableFrom(clazz)) {
      throw new IllegalStateException(
          "Input type " + clazz + " doesn't implement Extension " + type);
    }
    if (clazz.isInterface()) {
      throw new IllegalStateException("Input type " + clazz + " can't be interface!");
    }

    if (!clazz.isAnnotationPresent(Adaptive.class)) {
      if (StringUtils.isBlank(name)) {
        throw new IllegalStateException("Extension name is blank (Extension " + type + ")!");
      }
      if (!cachedClasses.get().containsKey(name)) {
        throw new IllegalStateException(
            "Extension name " + name + " doesn't exist (Extension " + type + ")!");
      }

      cachedNames.put(clazz, name);
      cachedClasses.get().put(name, clazz);
      cachedInstances.remove(name);
    } else {
      if (cachedAdaptiveClass == null) {
        throw new IllegalStateException(
            "Adaptive Extension doesn't exist (Extension " + type + ")!");
      }

      cachedAdaptiveClass = clazz;
      cachedAdaptiveInstance.set(null);
    }
  }

  /**
   * 会去获取标注了@Adaptive注解的方法，并创建一个类，并且编译生成一个自扩展类
   *
   * @return
   */
  @SuppressWarnings("unchecked")
  public T getAdaptiveExtension() {
    Object instance = cachedAdaptiveInstance.get();
    if (instance == null) {
      if (createAdaptiveInstanceError != null) {
        throw new IllegalStateException(
            "Failed to create adaptive instance: " + createAdaptiveInstanceError.toString(),
            createAdaptiveInstanceError);
      }

      synchronized (cachedAdaptiveInstance) {
        instance = cachedAdaptiveInstance.get();
        if (instance == null) {
          try {
            instance = createAdaptiveExtension();
            cachedAdaptiveInstance.set(instance);
          } catch (Throwable t) {
            createAdaptiveInstanceError = t;
            throw new IllegalStateException(
                "Failed to create adaptive instance: " + t.toString(), t);
          }
        }
      }
    }

    return (T) instance;
  }

  private IllegalStateException findException(String name) {
    for (Map.Entry<String, IllegalStateException> entry : exceptions.entrySet()) {
      if (entry.getKey().toLowerCase().contains(name.toLowerCase())) {
        return entry.getValue();
      }
    }
    StringBuilder buf =
        new StringBuilder("No such extension " + type.getName() + " by name " + name);

    int i = 1;
    for (Map.Entry<String, IllegalStateException> entry : exceptions.entrySet()) {
      if (i == 1) {
        buf.append(", possible causes: ");
      }

      buf.append("\r\n(");
      buf.append(i++);
      buf.append(") ");
      buf.append(entry.getKey());
      buf.append(":\r\n");
      buf.append(StringUtils.toString(entry.getValue()));
    }
    return new IllegalStateException(buf.toString());
  }

  /**
   * 1、先去缓存中获取缓存的扩展的Class信息，如果缓存的Class信息为空，则创建一个缓存的Class信息。如果创建后依旧无法找到，则抛出异常
   * 2、从实例缓存中获取一个实例，如果获取不到，则重新创建一个实例 3、如果是实例是一个包装类，则使用set方法注入包装类中的扩展点
   * 4、如果需要包装类，则去判断是否是包装类，是的话，实例被替换为包装类 5、如果对象有继承Dubbo的Lifecycle，则执行Lifecycle下的init方法。
   *
   * @param name 扩展点的名字
   * @param wrap 是否需要包装类
   * @return 创建的扩展点的实例
   */
  @SuppressWarnings("unchecked")
  private T createExtension(String name, boolean wrap) {
    // 1、获取并创建一个缓存的Class信息。如果最后实例化之后依旧未找到，则会抛出异常
    Class<?> clazz = getExtensionClasses().get(name);
    if (clazz == null) {
      throw findException(name);
    }
    try {
      T instance = (T) EXTENSION_INSTANCES.get(clazz);
      if (instance == null) {
        EXTENSION_INSTANCES.putIfAbsent(clazz, clazz.newInstance());
        instance = (T) EXTENSION_INSTANCES.get(clazz);
      }
      // 如果一个扩展点内有一个属性也是扩展点，那么就通过set方法进行注入
      injectExtension(instance);

      // 判断是否是包装类，如果是是的，则初始化包装类，并注入实例
      if (wrap) {
        List<Class<?>> wrapperClassesList = new ArrayList<>();
        if (cachedWrapperClasses != null) {
          wrapperClassesList.addAll(cachedWrapperClasses);
          wrapperClassesList.sort(WrapperComparator.COMPARATOR);
          Collections.reverse(wrapperClassesList);
        }

        if (CollectionUtils.isNotEmpty(wrapperClassesList)) {
          for (Class<?> wrapperClass : wrapperClassesList) {
            Wrapper wrapper = wrapperClass.getAnnotation(Wrapper.class);
            if (wrapper == null
                || (ArrayUtils.contains(wrapper.matches(), name)
                    && !ArrayUtils.contains(wrapper.mismatches(), name))) {
              instance =
                  injectExtension((T) wrapperClass.getConstructor(type).newInstance(instance));
            }
          }
        }
      }

      initExtension(instance);
      return instance;
    } catch (Throwable t) {
      throw new IllegalStateException(
          "Extension instance (name: "
              + name
              + ", class: "
              + type
              + ") couldn't be instantiated: "
              + t.getMessage(),
          t);
    }
  }

  private boolean containsExtension(String name) {
    return getExtensionClasses().containsKey(name);
  }

  private T injectExtension(T instance) {

    if (objectFactory == null) {
      return instance;
    }

    try {
      for (Method method : instance.getClass().getMethods()) {
        if (!isSetter(method)) {
          continue;
        }
        /** Check {@link DisableInject} to see if we need auto injection for this property */
        if (method.getAnnotation(DisableInject.class) != null) {
          continue;
        }
        Class<?> pt = method.getParameterTypes()[0];
        if (ReflectUtils.isPrimitives(pt)) {
          continue;
        }

        try {
          // 获得set方法的方法名称，除去了set三个字，并将第一个字幕转换为小写
          String property = getSetterProperty(method);
          Object object = objectFactory.getExtension(pt, property);
          if (object != null) {
            method.invoke(instance, object);
          }
        } catch (Exception e) {
          logger.error(
              "Failed to inject via method "
                  + method.getName()
                  + " of interface "
                  + type.getName()
                  + ": "
                  + e.getMessage(),
              e);
        }
      }
    } catch (Exception e) {
      logger.error(e.getMessage(), e);
    }
    return instance;
  }

  private void initExtension(T instance) {
    if (instance instanceof Lifecycle) {
      Lifecycle lifecycle = (Lifecycle) instance;
      lifecycle.initialize();
    }
  }

  /**
   * get properties name for setter, for instance: setVersion, return "version"
   *
   * <p>return "", if setter name with length less than 3
   */
  private String getSetterProperty(Method method) {
    return method.getName().length() > 3
        ? method.getName().substring(3, 4).toLowerCase() + method.getName().substring(4)
        : "";
  }

  /**
   * return true if and only if:
   *
   * <p>1, public
   *
   * <p>2, name starts with "set"
   *
   * <p>3, only has one parameter
   */
  private boolean isSetter(Method method) {
    return method.getName().startsWith("set")
        && method.getParameterTypes().length == 1
        && Modifier.isPublic(method.getModifiers());
  }

  private Class<?> getExtensionClass(String name) {
    if (type == null) {
      throw new IllegalArgumentException("Extension type == null");
    }
    if (name == null) {
      throw new IllegalArgumentException("Extension name == null");
    }
    return getExtensionClasses().get(name);
  }

  private Map<String, Class<?>> getExtensionClasses() {
    Map<String, Class<?>> classes = cachedClasses.get();
    if (classes == null) {
      synchronized (cachedClasses) {
        classes = cachedClasses.get();
        if (classes == null) {
          classes = loadExtensionClasses();
          cachedClasses.set(classes);
        }
      }
    }
    return classes;
  }

  /** synchronized in getExtensionClasses */
  private Map<String, Class<?>> loadExtensionClasses() {
    cacheDefaultExtensionName();

    Map<String, Class<?>> extensionClasses = new HashMap<>();
    // strategies的来源是通过使用Java的SPI，加载的Dubbo的配置路径
    for (LoadingStrategy strategy : strategies) {
      loadDirectory(
          extensionClasses,
          strategy.directory(),
          type.getName(),
          strategy.preferExtensionClassLoader(),
          strategy.overridden(),
          strategy.excludedPackages());
      loadDirectory(
          extensionClasses,
          strategy.directory(),
          type.getName().replace("org.apache", "com.alibaba"),
          strategy.preferExtensionClassLoader(),
          strategy.overridden(),
          strategy.excludedPackages());
    }

    return extensionClasses;
  }

  /** extract and cache default extension name if exists */
  private void cacheDefaultExtensionName() {
    // 获取该接口是的SPI注解，如果没有该注解，则返回的是null
    final SPI defaultAnnotation = type.getAnnotation(SPI.class);
    if (defaultAnnotation == null) {
      return;
    }
    // 判断@SPI注解的value属性的值
    String value = defaultAnnotation.value();
    // 保证他的值不为空字符串
    if ((value = value.trim()).length() > 0) {
      String[] names = NAME_SEPARATOR.split(value);
      // 如果默认实现的个数大于1个，则抛出异常
      if (names.length > 1) {
        throw new IllegalStateException(
            "More than 1 default extension name on extension "
                + type.getName()
                + ": "
                + Arrays.toString(names));
      }
      // 如果只有一个，则保存默认的实现类
      if (names.length == 1) {
        cachedDefaultName = names[0];
      }
    }
  }

  private void loadDirectory(Map<String, Class<?>> extensionClasses, String dir, String type) {
    loadDirectory(extensionClasses, dir, type, false, false);
  }

  /**
   * @param extensionClasses 最终ExtensionClass保存的位置，最终会将他缓存在ExtensionLoader的Class缓存中
   * @param dir 加载扩展点的路径
   * @param type 接口的名称
   * @param extensionLoaderClassLoaderFirst 是否先使用ExtensionLoader的类加载器来加载具体的扩展类
   * @param overridden 是否允许高优先级的实例，覆盖低优先级的实例
   * @param excludedPackages 这个目前全部都是空，看代码吧
   */
  private void loadDirectory(
      Map<String, Class<?>> extensionClasses,
      String dir,
      String type,
      boolean extensionLoaderClassLoaderFirst,
      boolean overridden,
      String... excludedPackages) {
    // 具体的一个扩展点的文件
    String fileName = dir + type;
    try {
      Enumeration<java.net.URL> urls = null;
      // 获取一个类加载器。1：先获取当前线程的应用上下文的加载器；2：如果获取失败，则获取ExtensionLoader的类加载器；3：如果获取失败，则获取系统类加载器
      ClassLoader classLoader = findClassLoader();

      // try to load from ExtensionLoader's ClassLoader first
      if (extensionLoaderClassLoaderFirst) {
        ClassLoader extensionLoaderClassLoader = ExtensionLoader.class.getClassLoader();
        if (ClassLoader.getSystemClassLoader() != extensionLoaderClassLoader) {
          urls = extensionLoaderClassLoader.getResources(fileName);
        }
      }

      if (urls == null || !urls.hasMoreElements()) {
        if (classLoader != null) {
          urls = classLoader.getResources(fileName);
        } else {
          urls = ClassLoader.getSystemResources(fileName);
        }
      }

      if (urls != null) {
        while (urls.hasMoreElements()) {
          // 最终读取到的值是类似于file:/类路径名
          java.net.URL resourceURL = urls.nextElement();
          loadResource(extensionClasses, classLoader, resourceURL, overridden, excludedPackages);
        }
      }
    } catch (Throwable t) {
      logger.error(
          "Exception occurred when loading extension class (interface: "
              + type
              + ", description file: "
              + fileName
              + ").",
          t);
    }
  }

  /**
   * 读取配置文件里面的值，然后将每一行解析出来，并加载到缓存中。如果该类没有公共的构造函数，则会抛出异常。然后会判断是否是包装类，是的话则会添加到包装类的缓存中。也会判断是否是
   *
   * @param extensionClasses 扩展类的一个Holder
   * @param classLoader 类加载器，用来加载配置文件中的实现类
   * @param resourceURL 需要加载的类的数据信息
   * @param overridden 是否重写
   * @param excludedPackages 如果扩展类的包是在excludePackages下，则不会进行加载
   */
  private void loadResource(
      Map<String, Class<?>> extensionClasses,
      ClassLoader classLoader,
      java.net.URL resourceURL,
      boolean overridden,
      String... excludedPackages) {
    try {
      try (BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(resourceURL.openStream(), StandardCharsets.UTF_8))) {
        String line;
        while ((line = reader.readLine()) != null) {
          final int ci = line.indexOf('#');
          if (ci >= 0) {
            line = line.substring(0, ci);
          }
          line = line.trim();
          if (line.length() > 0) {
            try {
              String name = null;
              int i = line.indexOf('=');
              if (i > 0) {
                name = line.substring(0, i).trim();
                line = line.substring(i + 1).trim();
              }
              if (line.length() > 0 && !isExcluded(line, excludedPackages)) {
                loadClass(
                    extensionClasses,
                    resourceURL,
                    Class.forName(line, true, classLoader),
                    name,
                    overridden);
              }
            } catch (Throwable t) {
              IllegalStateException e =
                  new IllegalStateException(
                      "Failed to load extension class (interface: "
                          + type
                          + ", class line: "
                          + line
                          + ") in "
                          + resourceURL
                          + ", cause: "
                          + t.getMessage(),
                      t);
              exceptions.put(line, e);
            }
          }
        }
      }
    } catch (Throwable t) {
      logger.error(
          "Exception occurred when loading extension class (interface: "
              + type
              + ", class file: "
              + resourceURL
              + ") in "
              + resourceURL,
          t);
    }
  }

  private boolean isExcluded(String className, String... excludedPackages) {
    if (excludedPackages != null) {
      for (String excludePackage : excludedPackages) {
        if (className.startsWith(excludePackage + ".")) {
          return true;
        }
      }
    }
    return false;
  }

  private void loadClass(
      Map<String, Class<?>> extensionClasses,
      java.net.URL resourceURL,
      Class<?> clazz,
      String name,
      boolean overridden)
      throws NoSuchMethodException {
    if (!type.isAssignableFrom(clazz)) {
      throw new IllegalStateException(
          "Error occurred when loading extension class (interface: "
              + type
              + ", class line: "
              + clazz.getName()
              + "), class "
              + clazz.getName()
              + " is not subtype of interface.");
    }
    if (clazz.isAnnotationPresent(Adaptive.class)) {
      cacheAdaptiveClass(clazz, overridden);
    } else if (isWrapperClass(clazz)) {
      cacheWrapperClass(clazz);
    } else {
      // 获得一个公共构造器，如果没有则抛出异常
      clazz.getConstructor();
      if (StringUtils.isEmpty(name)) {
        name = findAnnotationName(clazz);
        // 主要是判断标注了@Extension注解的实现类
        if (name.length() == 0) {
          throw new IllegalStateException(
              "No such extension name for the class "
                  + clazz.getName()
                  + " in the config "
                  + resourceURL);
        }
      }

      String[] names = NAME_SEPARATOR.split(name);
      if (ArrayUtils.isNotEmpty(names)) {
        cacheActivateClass(clazz, names[0]);
        for (String n : names) {
          // 保存扩展点的类的名称
          cacheName(clazz, n);
          saveInExtensionClass(extensionClasses, clazz, n, overridden);
        }
      }
    }
  }

  /** cache name */
  private void cacheName(Class<?> clazz, String name) {
    if (!cachedNames.containsKey(clazz)) {
      cachedNames.put(clazz, name);
    }
  }

  /** put clazz in extensionClasses */
  private void saveInExtensionClass(
      Map<String, Class<?>> extensionClasses, Class<?> clazz, String name, boolean overridden) {
    Class<?> c = extensionClasses.get(name);
    if (c == null || overridden) {
      extensionClasses.put(name, clazz);
    } else if (c != clazz) {
      String duplicateMsg =
          "Duplicate extension "
              + type.getName()
              + " name "
              + name
              + " on "
              + c.getName()
              + " and "
              + clazz.getName();
      logger.error(duplicateMsg);
      throw new IllegalStateException(duplicateMsg);
    }
  }

  /**
   * cache Activate class which is annotated with <code>Activate</code>
   *
   * <p>for compatibility, also cache class with old alibaba Activate annotation
   */
  private void cacheActivateClass(Class<?> clazz, String name) {
    Activate activate = clazz.getAnnotation(Activate.class);
    if (activate != null) {
      cachedActivates.put(name, activate);
    } else {
      // support com.alibaba.dubbo.common.extension.Activate
      com.alibaba.dubbo.common.extension.Activate oldActivate =
          clazz.getAnnotation(com.alibaba.dubbo.common.extension.Activate.class);
      if (oldActivate != null) {
        cachedActivates.put(name, oldActivate);
      }
    }
  }

  /** cache Adaptive class which is annotated with <code>Adaptive</code> */
  private void cacheAdaptiveClass(Class<?> clazz, boolean overridden) {
    if (cachedAdaptiveClass == null || overridden) {
      cachedAdaptiveClass = clazz;
    } else if (!cachedAdaptiveClass.equals(clazz)) {
      throw new IllegalStateException(
          "More than 1 adaptive class found: "
              + cachedAdaptiveClass.getName()
              + ", "
              + clazz.getName());
    }
  }

  /**
   * cache wrapper class
   *
   * <p>like: ProtocolFilterWrapper, ProtocolListenerWrapper
   */
  private void cacheWrapperClass(Class<?> clazz) {
    if (cachedWrapperClasses == null) {
      cachedWrapperClasses = new ConcurrentHashSet<>();
    }
    cachedWrapperClasses.add(clazz);
  }

  /**
   * test if clazz is a wrapper class
   *
   * <p>which has Constructor with given class type as its only argument
   */
  private boolean isWrapperClass(Class<?> clazz) {
    try {
      // 如果拿到了type类型参数的构造器，则说明是wrapper类
      clazz.getConstructor(type);
      return true;
    } catch (NoSuchMethodException e) {
      // 抛出异常，则说明没有该类型的构造器，说明不是包装类
      return false;
    }
  }

  @SuppressWarnings("deprecation")
  private String findAnnotationName(Class<?> clazz) {
    org.apache.dubbo.common.Extension extension =
        clazz.getAnnotation(org.apache.dubbo.common.Extension.class);
    if (extension != null) {
      return extension.value();
    }

    String name = clazz.getSimpleName();
    if (name.endsWith(type.getSimpleName())) {
      name = name.substring(0, name.length() - type.getSimpleName().length());
    }
    return name.toLowerCase();
  }

  @SuppressWarnings("unchecked")
  private T createAdaptiveExtension() {
    try {
      return injectExtension((T) getAdaptiveExtensionClass().newInstance());
    } catch (Exception e) {
      throw new IllegalStateException(
          "Can't create adaptive extension " + type + ", cause: " + e.getMessage(), e);
    }
  }

  /**
   * 在初始化扩展点的时候，就会去判断是否是自适应的扩展点，是的话，则会添加到自适应扩展点的缓存中。自适应扩展点有且仅有一个， 在加载的时候，如果出现多个，并且不允许覆盖，则会抛出异常
   *
   * @return 获取自适应扩展点的class信息
   */
  private Class<?> getAdaptiveExtensionClass() {
    getExtensionClasses();
    if (cachedAdaptiveClass != null) {
      return cachedAdaptiveClass;
    }
    return cachedAdaptiveClass = createAdaptiveExtensionClass();
  }

  private Class<?> createAdaptiveExtensionClass() {
    // 生成扩展点的代码，未标记为@Adaptive的方法会直接抛出未支持的异常
    String code = new AdaptiveClassCodeGenerator(type, cachedDefaultName).generate();
    ClassLoader classLoader = findClassLoader();
    org.apache.dubbo.common.compiler.Compiler compiler =
        ExtensionLoader.getExtensionLoader(org.apache.dubbo.common.compiler.Compiler.class)
            .getAdaptiveExtension();
    return compiler.compile(code, classLoader);
  }

  @Override
  public String toString() {
    return this.getClass().getName() + "[" + type.getName() + "]";
  }
}
