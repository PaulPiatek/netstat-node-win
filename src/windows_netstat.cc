// had to put windows header files before nodes,
// otherwise electron-rebuild would fail.... :/
#include "include.h"

using namespace v8;

void GetConnections(const FunctionCallbackInfo<Value> &args)
{
  Isolate *isolate = args.GetIsolate();
  Local<Array> result_list = Array::New(isolate);
  getConnections(&result_list, isolate);

  args.GetReturnValue().Set(result_list);
}

void init(Local<Object> exports, Local<Value> module, Local<Context> context)
{
  NODE_SET_METHOD(exports, "connections", GetConnections);
}

NODE_MODULE_CONTEXT_AWARE(NODE_GYP_MODULE_NAME, init)