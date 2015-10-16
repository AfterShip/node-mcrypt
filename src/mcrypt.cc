

#include "mcrypt.h"

using namespace v8;

Nan::Persistent<Function> MCrypt::constructor;

MCrypt::MCrypt(Nan::NAN_METHOD_ARGS_TYPE info): 
    checkKeySize(true), 
    checkIvSize(true),
    algo(info[0]), 
    mode(info[1]) {

    mcrypt_ = mcrypt_module_open(*algo, NULL, *mode, NULL);
};

MCrypt::~MCrypt() {
    mcrypt_module_close(mcrypt_);
};


template <int (*modify)(MCRYPT mcrypt, void* target, int length)>
char* MCrypt::transform(const char* plainText, size_t* length, int* result) { 
    const size_t origLength = *length;

    // determine allocation size if the cipher algorithm is block mode
    // block mode algorithm needs to fit in modulus of block size
    // and it needs to padding space if not fit into block size
    if (mcrypt_enc_is_block_algorithm(mcrypt_) == 1) {
        size_t blockSize = mcrypt_enc_get_block_size(mcrypt_);
        *length = (((*length - 1) / blockSize) + 1) * blockSize;
    }

    char* targetData = new char[*length]();
    std::copy(plainText, plainText + origLength, targetData);
    
    // copy of the key and iv due to mcrypt_generic_init not accepts 
    // const char for key and iv. direct passing is not safe because
    // iv and key could be modified by mcrypt_generic_init in this case
    char *keyBuf = new char[key.length()];
    key.copy(keyBuf, key.length());

    char *ivBuf = new char[iv.length()];
    iv.copy(ivBuf, iv.length());
    
    if ((*result = mcrypt_generic_init(mcrypt_, keyBuf, key.length(), ivBuf)) < 0) {
        delete keyBuf;
        delete ivBuf;
        return targetData;
    }

    if ((*result = modify(mcrypt_, targetData, *length)) != 0) {
        delete keyBuf;
        delete ivBuf;
        return targetData;
    }

    *result = mcrypt_generic_deinit(mcrypt_);

    delete keyBuf;
    delete ivBuf;
    return targetData;
}

std::vector<size_t> MCrypt::getKeySizes() {
    
    int count = 0;
    int* sizes = mcrypt_enc_get_supported_key_sizes(mcrypt_, &count);

    if (count <= 0) {
        mcrypt_free(sizes);

        size_t size = mcrypt_enc_get_key_size(mcrypt_);

        if (size > 0) {
            std::vector<size_t> keySizes(1);
            keySizes[0] = size;
            return keySizes;
        }

        std::vector<size_t> keySizes(0);
        return keySizes;
    }

    std::vector<size_t> keySizes(count);

    for (int i = 0; i < count; i++) {
        keySizes[i] = sizes[i];
    }

    mcrypt_free(sizes);
    
    return keySizes;
}

NAN_METHOD(MCrypt::New) {
    Nan::HandleScope scope;
    
    if (!info.IsConstructCall()) {
        Local<Value> argv[] = {info[0], info[1]};
        Local<Function> cons = Nan::New<Function>(constructor);
        info.GetReturnValue().Set(cons->NewInstance(2, argv));
    }

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing parameters. Algorithm and mode should be specified.");
    }

    MCrypt* mcrypt = new MCrypt(info);

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    mcrypt->Wrap(info.This());

    info.GetReturnValue().Set(info.This());
}

NAN_METHOD(MCrypt::Open) {
    Nan::HandleScope scope;

    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing parameter. Key should be specified.");
    }
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());
    
    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (info[0]->IsString()) {
        Nan::Utf8String value(info[0]);
    
        mcrypt->key = std::string(*value, value.length());

    } else if (node::Buffer::HasInstance(info[0])) { 
    
        mcrypt->key = std::string(node::Buffer::Data(info[0]), node::Buffer::Length(info[0]));

    } else {
        Nan::ThrowTypeError("Key has got incorrect type. Should be Buffer or String.");
    }

    
    
    if (mcrypt->checkKeySize) {
        std::vector<size_t> keySizes = mcrypt->getKeySizes();
    
        if (keySizes.size() > 0) {

            bool invalid = true;
            
            std::stringstream serror;
            
            serror << "Invalid key size. Available key size are [";
            
            for(size_t i = 0; i < keySizes.size(); i++) {
                
                if (i != 0) {
                    serror << ", ";
                }
                
                serror << keySizes[i];
                
                if (keySizes[i] == mcrypt->key.length()) {
                    invalid = false;
                }
            }

            serror << "]";
            
            std::string error = serror.str();

            if (invalid) {
                Nan::ThrowTypeError(error.c_str());
            }
        }
    }

    if (info[1]->IsUndefined()) {
        return;
    }

    size_t ivLen = 0;

    if (info[1]->IsString()) {
        
        Nan::Utf8String value(info[1]);

        ivLen = value.length();
        mcrypt->iv = std::string(*value, ivLen);

    } else if (node::Buffer::HasInstance(info[1])) {

        ivLen = node::Buffer::Length(info[1]);
        mcrypt->iv = std::string(node::Buffer::Data(info[1]), ivLen);
    } else {
        Nan::ThrowTypeError("Iv has got incorrect type. Should be Buffer or String.");
    }

    if (mcrypt->checkIvSize) {
        if ((size_t)mcrypt_enc_get_iv_size(mcrypt->mcrypt_) != ivLen) {
            Nan::ThrowTypeError("Invalid iv size. You can determine iv size using getIvSize()");
        }
    }
    
    return;
}

NAN_METHOD(MCrypt::Encrypt) {
    Nan::HandleScope scope;
    
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing parameter. Plaintext should be specified.");
    }
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This()); 
    
    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int result = 0;
    char* cipherText = {0};
    size_t length = 0;

    if (info[0]->IsString()) {

        Nan::Utf8String value(info[0]);
        length = value.length();
        cipherText = mcrypt->transform<mcrypt_generic>(*value, &length, &result);

    } else if(node::Buffer::HasInstance(info[0])) {

        length = node::Buffer::Length(info[0]);
        cipherText = mcrypt->transform<mcrypt_generic>(node::Buffer::Data(info[0]), &length, &result); 
        
    } else {
        Nan::ThrowTypeError("Plaintext has got incorrect type. Should be Buffer or String.");
    }
    
    if (result != 0) {
        const char* error = mcrypt_strerror(result);
        delete[] cipherText;
        Nan::ThrowError(error);
    }

    Local<Object> retVal = Nan::NewBuffer(cipherText, length).ToLocalChecked();
    delete[] cipherText;

    info.GetReturnValue().Set(retVal);
}

NAN_METHOD(MCrypt::Decrypt) {
    Nan::HandleScope scope;
    
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing parameter. Plaintext should be specified.");
    }
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());
    
    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int result = 0;
    char* cipherText = {0};
    size_t length = 0;

    if (info[0]->IsString()) {

        Nan::Utf8String value(info[0]);
        length = value.length();
        cipherText = mcrypt->transform<mdecrypt_generic>(*value, &length, &result);

    } else if (node::Buffer::HasInstance(info[0])) {
        length = node::Buffer::Length(info[0]);
        cipherText = mcrypt->transform<mdecrypt_generic>(node::Buffer::Data(info[0]), &length, &result);

    } else {
        Nan::ThrowTypeError("Ciphertext has got incorrect type. Should be Buffer or String.");
    }
    
    if (result != 0) {
        const char* error = mcrypt_strerror(result);
        delete[] cipherText;
        Nan::ThrowError(error);
    }

    Local<Object> retVal = Nan::NewBuffer(cipherText, length).ToLocalChecked();
    delete[] cipherText;

    info.GetReturnValue().Set(retVal);
}

NAN_METHOD(MCrypt::ValidateKeySize) {
    Nan::HandleScope scope;

    if(info.Length() == 0) {
        return;
    }

    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());
    Local<Boolean> state = info[0]->ToBoolean();
    mcrypt->checkKeySize = state->Value();

    return;
}

NAN_METHOD(MCrypt::ValidateIvSize) {
    Nan::HandleScope scope;

    if(info.Length() == 0) {
        return;
    }

    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());
    Local<Boolean> state = info[0]->ToBoolean();
    mcrypt->checkIvSize = state->Value();

    return;
}

NAN_METHOD(MCrypt::SelfTest) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    if (mcrypt_enc_self_test(mcrypt->mcrypt_) == 0) {
        info.GetReturnValue().Set(Nan::True());
    }

    info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::IsBlockAlgorithmMode) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (mcrypt_enc_is_block_algorithm_mode(mcrypt->mcrypt_) == 1) {
        info.GetReturnValue().Set(Nan::True());
    }
    
    info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::IsBlockAlgorithm) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (mcrypt_enc_is_block_algorithm(mcrypt->mcrypt_) == 1) {
        info.GetReturnValue().Set(Nan::True());
    }
    
    info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::IsBlockMode) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (mcrypt_enc_is_block_mode(mcrypt->mcrypt_) == 1) {
        info.GetReturnValue().Set(Nan::True());
    }
    
    info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::GetBlockSize) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int blockSize = mcrypt_enc_get_block_size(mcrypt->mcrypt_);
    
    info.GetReturnValue().Set(Nan::New<Number>(blockSize));
}

NAN_METHOD(MCrypt::GetKeySize) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int keySize = mcrypt_enc_get_key_size(mcrypt->mcrypt_);

    info.GetReturnValue().Set(Nan::New<Number>(keySize));
}

NAN_METHOD(MCrypt::GetSupportedKeySizes) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    std::vector<size_t> keySizes = mcrypt->getKeySizes();

    Local<Array> array = Nan::New<Array>(keySizes.size());
    
    for (size_t i = 0; i < keySizes.size(); i++) {
        array->Set(i, Nan::New<Number>(keySizes[i]));
    }
    
    info.GetReturnValue().Set(array);
}

NAN_METHOD(MCrypt::GetIvSize) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int ivSize = mcrypt_enc_get_iv_size(mcrypt->mcrypt_);
    
    info.GetReturnValue().Set(Nan::New<Number>(ivSize));
}

NAN_METHOD(MCrypt::HasIv) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (mcrypt_enc_mode_has_iv(mcrypt->mcrypt_) == 1) {
        info.GetReturnValue().Set(Nan::True());
    }
    
    info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::GetAlgorithmName) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    char* name = mcrypt_enc_get_algorithms_name(mcrypt->mcrypt_);
    Local<String> ret = Nan::New<String>(name).ToLocalChecked();
    mcrypt_free(name);

    info.GetReturnValue().Set(ret);
}

NAN_METHOD(MCrypt::GetModeName) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    char* name = mcrypt_enc_get_modes_name(mcrypt->mcrypt_);
    Local<String> ret = Nan::New<String>(name).ToLocalChecked();
    mcrypt_free(name);

    info.GetReturnValue().Set(ret);
}

NAN_METHOD(MCrypt::GenerateIv) {
    Nan::HandleScope scope;
    
    MCrypt* mcrypt = Nan::ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int ivSize = mcrypt_enc_get_iv_size(mcrypt->mcrypt_);
    
    Local<Object> buffer = Nan::NewBuffer(ivSize).ToLocalChecked();
    
    char* iv = node::Buffer::Data(buffer);
    
    while(ivSize) {
        iv[--ivSize] = 255.0 * std::rand() / RAND_MAX;
    }

    info.GetReturnValue().Set(buffer);
}

NAN_METHOD(MCrypt::GetAlgorithmNames) {
    Nan::HandleScope scope;
    
    Nan::Utf8String path(info[0]);
    
    int size = 0;
    char** algos = mcrypt_list_algorithms(*path, &size);
    
    Local<Array> array = Nan::New<Array>(size);
    
    if (array.IsEmpty()) {
        info.GetReturnValue().Set(Nan::New<Array>());
    }
    
    for (int i = 0; i < size; i++) {
        array->Set(i, Nan::New<String>(algos[i]).ToLocalChecked());
    }
    
    mcrypt_free_p(algos, size);
    
    info.GetReturnValue().Set(array);
}

NAN_METHOD(MCrypt::GetModeNames) {
    Nan::HandleScope scope;
    
    Nan::Utf8String path(info[0]);
    
    int size = 0;
    char** modes = mcrypt_list_modes(*path, &size);
    
    Local<Array> array = Nan::New<Array>(size);
    
    if (array.IsEmpty())
        info.GetReturnValue().Set(Nan::New<Array>());
    
    for (int i = 0; i < size; i++) {
        array->Set(i, Nan::New<String>(modes[i]).ToLocalChecked());
    }
    
    mcrypt_free_p(modes, size);

    info.GetReturnValue().Set(array);
}

void MCrypt::Init(Handle<Object> exports) {
    Nan::HandleScope scope;

    Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
    tpl->SetClassName(Nan::New("MCrypt").ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1); 

    // prototype
    Nan::SetPrototypeMethod(tpl, "encrypt", Encrypt);
    Nan::SetPrototypeMethod(tpl, "decrypt", Decrypt);
    Nan::SetPrototypeMethod(tpl, "open", Open);
    Nan::SetPrototypeMethod(tpl, "validateKeySize", ValidateKeySize);
    Nan::SetPrototypeMethod(tpl, "validateIvSize", ValidateIvSize);
    Nan::SetPrototypeMethod(tpl, "selfTest", SelfTest);
    Nan::SetPrototypeMethod(tpl, "isBlockAlgorithmMode", IsBlockAlgorithmMode);
    Nan::SetPrototypeMethod(tpl, "isBlockAlgorithm", IsBlockAlgorithm);
    Nan::SetPrototypeMethod(tpl, "isBlockMode", IsBlockMode);
    Nan::SetPrototypeMethod(tpl, "getBlockSize", GetBlockSize);
    Nan::SetPrototypeMethod(tpl, "getKeySize", GetKeySize);
    Nan::SetPrototypeMethod(tpl, "getSupportedKeySizes", GetSupportedKeySizes);
    Nan::SetPrototypeMethod(tpl, "getIvSize", GetIvSize);
    Nan::SetPrototypeMethod(tpl, "hasIv", HasIv);
    Nan::SetPrototypeMethod(tpl, "getAlgorithmName", GetAlgorithmName);
    Nan::SetPrototypeMethod(tpl, "getModeName", GetModeName);
    Nan::SetPrototypeMethod(tpl, "generateIv", GenerateIv);

    // exports
    constructor.Reset(tpl->GetFunction());
    exports->Set(Nan::New("MCrypt").ToLocalChecked(), tpl->GetFunction());
    Nan::SetMethod(exports, "getAlgorithmNames", GetAlgorithmNames);
    Nan::SetMethod(exports, "getModeNames", GetModeNames);
}

NODE_MODULE(mcrypt, MCrypt::Init)
