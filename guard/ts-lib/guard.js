let imports = {};
imports['__wbindgen_placeholder__'] = module.exports;
let wasm;
const { existsSync } = require(`fs`);
const { resolve } = require(`path`);
const { TextDecoder, TextEncoder } = require(`util`);

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachedUint8Memory0 = null;

function getUint8Memory0() {
    if (cachedUint8Memory0 === null || cachedUint8Memory0.byteLength === 0) {
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function getObject(idx) { return heap[idx]; }

function isLikeNone(x) {
    return x === undefined || x === null;
}

let cachedFloat64Memory0 = null;

function getFloat64Memory0() {
    if (cachedFloat64Memory0 === null || cachedFloat64Memory0.byteLength === 0) {
        cachedFloat64Memory0 = new Float64Array(wasm.memory.buffer);
    }
    return cachedFloat64Memory0;
}

let cachedInt32Memory0 = null;

function getInt32Memory0() {
    if (cachedInt32Memory0 === null || cachedInt32Memory0.byteLength === 0) {
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachedInt32Memory0;
}

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let WASM_VECTOR_LEN = 0;

let cachedTextEncoder = new TextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedUint32Memory0 = null;

function getUint32Memory0() {
    if (cachedUint32Memory0 === null || cachedUint32Memory0.byteLength === 0) {
        cachedUint32Memory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachedUint32Memory0;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    const mem = getUint32Memory0();
    for (let i = 0; i < array.length; i++) {
        mem[ptr / 4 + i] = addHeapObject(array[i]);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_exn_store(addHeapObject(e));
    }
}
/**
*/
module.exports.OutputFormatType = Object.freeze({ SingleLineSummary:0,"0":"SingleLineSummary",JSON:1,"1":"JSON",YAML:2,"2":"YAML",Junit:3,"3":"Junit",Sarif:4,"4":"Sarif", });
/**
*/
module.exports.ShowSummaryType = Object.freeze({ All:0,"0":"All",Pass:1,"1":"Pass",Fail:2,"2":"Fail",Skip:3,"3":"Skip",None:4,"4":"None", });

const ValidateBuilderFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_validatebuilder_free(ptr >>> 0));
/**
* .
* A builder to help construct the `Validate` command
*/
class ValidateBuilder {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(ValidateBuilder.prototype);
        obj.__wbg_ptr = ptr;
        ValidateBuilderFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ValidateBuilderFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_validatebuilder_free(ptr);
    }
    /**
    * a list of paths that point to rule files, or a directory containing rule files on a local machine. Only files that end with .guard or .ruleset will be evaluated
    * conflicts with payload
    * @param {(string)[]} rules
    * @returns {ValidateBuilder}
    */
    rules(rules) {
        const ptr = this.__destroy_into_raw();
        const ptr0 = passArrayJsValueToWasm0(rules, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.validatebuilder_rules(ptr, ptr0, len0);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * a list of paths that point to data files, or a directory containing data files  for the rules to be evaluated against. Only JSON, or YAML files will be used
    * conflicts with payload
    * @param {(string)[]} data
    * @returns {ValidateBuilder}
    */
    data(data) {
        const ptr = this.__destroy_into_raw();
        const ptr0 = passArrayJsValueToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.validatebuilder_data(ptr, ptr0, len0);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * Controls if the summary table needs to be displayed. --show-summary fail (default) or --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip)
    * default is failed
    * must be set to none if used together with the structured flag
    * @param {any[]} args
    * @returns {ValidateBuilder}
    */
    showSummary(args) {
        const ptr = this.__destroy_into_raw();
        const ptr0 = passArrayJsValueToWasm0(args, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.validatebuilder_showSummary(ptr, ptr0, len0);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * a list of paths that point to data files, or a directory containing data files to be merged with the data argument and then the  rules will be evaluated against them. Only JSON, or YAML files will be used
    * @param {(string)[]} input_params
    * @returns {ValidateBuilder}
    */
    input_params(input_params) {
        const ptr = this.__destroy_into_raw();
        const ptr0 = passArrayJsValueToWasm0(input_params, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.validatebuilder_input_params(ptr, ptr0, len0);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * Specify the format in which the output should be displayed
    * default is single-line-summary
    * if junit is used, `structured` attributed must be set to true
    * @param {OutputFormatType} output
    * @returns {ValidateBuilder}
    */
    outputFormat(output) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.validatebuilder_outputFormat(ptr, output);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * Tells the command that rules, and data will be passed via a reader, as a json payload.
    * Conflicts with both rules, and data
    * default is false
    * @param {boolean} arg
    * @returns {ValidateBuilder}
    */
    payload(arg) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.validatebuilder_payload(ptr, arg);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * Validate files in a directory ordered alphabetically, conflicts with `last_modified` field
    * @param {boolean} arg
    * @returns {ValidateBuilder}
    */
    alphabetical(arg) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.validatebuilder_alphabetical(ptr, arg);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * Validate files in a directory ordered by last modified times, conflicts with `alphabetical` field
    * @param {boolean} arg
    * @returns {ValidateBuilder}
    */
    last_modified(arg) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.validatebuilder_last_modified(ptr, arg);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * Output verbose logging, conflicts with `structured` field
    * default is false
    * @param {boolean} arg
    * @returns {ValidateBuilder}
    */
    verbose(arg) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.validatebuilder_verbose(ptr, arg);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * Print the parse tree in a json format. This can be used to get more details on how the clauses were evaluated
    * conflicts with the `structured` attribute
    * default is false
    * @param {boolean} arg
    * @returns {ValidateBuilder}
    */
    print_json(arg) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.validatebuilder_print_json(ptr, arg);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    * Prints the output which must be specified to JSON/YAML/JUnit in a structured format
    * Conflicts with the following attributes `verbose`, `print-json`, `output-format` when set
    * to "single-line-summary", show-summary when set to anything other than "none"
    * default is false
    * @param {boolean} arg
    * @returns {ValidateBuilder}
    */
    structured(arg) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.validatebuilder_structured(ptr, arg);
        return ValidateBuilder.__wrap(ret);
    }
    /**
    */
    constructor() {
        const ret = wasm.validatebuilder_new();
        this.__wbg_ptr = ret >>> 0;
        return this;
    }
    /**
    * @param {string} payload
    * @returns {any}
    */
    tryBuildAndExecute(payload) {
        try {
            const ptr = this.__destroy_into_raw();
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(payload, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            wasm.validatebuilder_tryBuildAndExecute(retptr, ptr, ptr0, len0);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            var r2 = getInt32Memory0()[retptr / 4 + 2];
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
module.exports.ValidateBuilder = ValidateBuilder;

module.exports.__wbindgen_string_new = function(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
};

module.exports.__wbindgen_try_into_number = function(arg0) {
    let result;
try { result = +getObject(arg0) } catch (e) { result = e }
const ret = result;
return addHeapObject(ret);
};

module.exports.__wbindgen_number_get = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'number' ? obj : undefined;
    getFloat64Memory0()[arg0 / 8 + 1] = isLikeNone(ret) ? 0 : ret;
    getInt32Memory0()[arg0 / 4 + 0] = !isLikeNone(ret);
};

module.exports.__wbindgen_object_drop_ref = function(arg0) {
    takeObject(arg0);
};

module.exports.__wbg_existsSync_2b54de1ac768abd3 = function() { return handleError(function (arg0, arg1) {
    const ret = existsSync(getStringFromWasm0(arg0, arg1));
    return ret;
}, arguments) };

module.exports.__wbg_resolve_88cfd218e55df477 = function() { return handleError(function (arg0, arg1, arg2) {
    const ret = resolve(getStringFromWasm0(arg1, arg2));
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len1;
    getInt32Memory0()[arg0 / 4 + 0] = ptr1;
}, arguments) };

module.exports.__wbindgen_string_get = function(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'string' ? obj : undefined;
    var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    getInt32Memory0()[arg0 / 4 + 1] = len1;
    getInt32Memory0()[arg0 / 4 + 0] = ptr1;
};

module.exports.__wbindgen_throw = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

const path = require('path').join(__dirname, 'guard_bg.wasm');
const bytes = require('fs').readFileSync(path);

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
wasm = wasmInstance.exports;
module.exports.__wasm = wasm;

