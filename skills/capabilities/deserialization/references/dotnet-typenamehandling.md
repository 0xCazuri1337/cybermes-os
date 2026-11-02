# .NET Deserialization: TypeNameHandling

## Scope
Newtonsoft.Json with TypeNameHandling != None, BinaryFormatter, ObjectStateFormatter, ViewState, LosFormatter.

## Signals
- JSON containing $type field.
- ViewState / __VIEWSTATE parameters.
- .NET stack traces (Newtonsoft.Json, System.Runtime.Serialization).

## Detection
- Send {"$type":"System.Windows.Data.ObjectDataProvider, ..."} payloads.
- Check ViewState MAC validation (if MAC disabled, tamper).
- Use ysoserial.net for gadget chains (ObjectDataProvider, TextFormattingRunProperties).

## OOB validation
Use callback_host for DNS/HTTP callbacks (e.g. via System.Diagnostics.Process or WebClient).

## False positives
- SerializationBinder restricting types.
- ViewState MAC enabled and key unknown.
