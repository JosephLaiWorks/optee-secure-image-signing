#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>
#include <save_pic_ta.h>
#include <string.h>
#include <pta_system.h>

static TEE_Result write_raw_object(const char *id, const void *data, size_t size);


// private_key 宣告
static TEE_ObjectHandle private_key = TEE_HANDLE_NULL;

static TEE_Result export_public_key(uint32_t param_types, TEE_Param params[4]);

static TEE_Result init_private_key(void) {
    TEE_Result res;
    const char key_id[] = "rsa_key";
    const size_t key_id_len = sizeof(key_id) - 1;
    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;

    // 嘗試載入已存在的 RSA key
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                   TEE_DATA_FLAG_ACCESS_READ, &persistent_key);
    if (res == TEE_SUCCESS) {
        IMSG("[RSA] Loaded RSA key from secure storage");
        private_key = persistent_key;
        return TEE_SUCCESS;
    }

    IMSG("[RSA] Key not found. Generating new RSA key...");

    // 建立 transient RSA key
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 2048, &transient_key);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to allocate transient object: 0x%x", res);
        return res;
    }

    res = TEE_GenerateKey(transient_key, 2048, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to generate RSA key: 0x%x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    // 儲存 key 為 persistent object（重點：要先做這一步）
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                     TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
                                     transient_key, NULL, 0, &persistent_key);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to persist RSA key: 0x%x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    private_key = persistent_key;
    TEE_FreeTransientObject(transient_key);  // 釋放 transient handle

    // 導出 modulus
    uint8_t modulus[256];
    uint32_t mod_len = sizeof(modulus);
    res = TEE_GetObjectBufferAttribute(private_key, TEE_ATTR_RSA_MODULUS, modulus, &mod_len);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to get modulus: 0x%x", res);
        return res;
    }

    res = write_raw_object("rsa_modulus", modulus, mod_len);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to store modulus blob: 0x%x", res);
        return res;
    }
    IMSG("Successfully wrote object 'rsa_modulus' (%u bytes)", mod_len);

    // 導出 exponent
    uint8_t exponent_buf[8];  // 抓大一點以容納最多 64-bit 的 exponent
    uint32_t exp_len = sizeof(exponent_buf);
    res = TEE_GetObjectBufferAttribute(private_key, TEE_ATTR_RSA_PUBLIC_EXPONENT, exponent_buf, &exp_len);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to get exponent: 0x%x", res);
        return res;
    }

    IMSG("[DEBUG] Writing rsa_exponent, length = %u", exp_len);
    res = write_raw_object("rsa_exponent", exponent_buf, exp_len);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to store exponent blob: 0x%x", res);
        return res;
    }
    IMSG("Successfully wrote object 'rsa_exponent' (%u bytes)", exp_len);

    IMSG("[RSA] New RSA key generated and saved to secure storage");
    return TEE_SUCCESS;
}


/*
static TEE_Result init_private_key(void) {
    TEE_Result res;
    const char key_id[] = "rsa_key";
    const size_t key_id_len = sizeof(key_id) - 1;
    TEE_ObjectHandle persistent_key;

    // 讀取已存在金鑰
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                   TEE_DATA_FLAG_ACCESS_READ, &persistent_key);
    if (res == TEE_SUCCESS) {
        private_key = persistent_key;
        IMSG("[RSA] Loaded RSA key from secure storage");
        return TEE_SUCCESS;
    }

    IMSG("[RSA] Key not found. Generating new RSA key...");

    // 產生 transient RSA key
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 2048, &private_key);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_GenerateKey(private_key, 2048, NULL, 0);
    if (res != TEE_SUCCESS) {
    	// add for debuging
    	EMSG("PANIC: Failed to generate RSA key, res=0x%x", res);
    	
        TEE_FreeTransientObject(private_key);
        return res;
    }

    // 直接儲存 transient key 至 persistent object
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, key_id, key_id_len,
                                     TEE_DATA_FLAG_ACCESS_WRITE |
                                     TEE_DATA_FLAG_ACCESS_READ |
                                     TEE_DATA_FLAG_ACCESS_WRITE_META,
                                     private_key, NULL, 0, &persistent_key);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(private_key);
        return res;
    }

    private_key = persistent_key;
    IMSG("[RSA] RSA key generated and securely stored");
    return TEE_SUCCESS;
}

*/



//  SHA256 雜湊後執行 RSA 簽章
static TEE_Result sign_photo(uint8_t *photo_data, size_t data_len,
                             uint8_t *sig, uint32_t *sig_len) {
    TEE_Result res;
    TEE_OperationHandle op_hash = TEE_HANDLE_NULL;
    TEE_OperationHandle op_sign = TEE_HANDLE_NULL;
    uint8_t hash[32];
    uint32_t hash_len = sizeof(hash);

    IMSG("[RSA] Starting SHA-256 hashing...");

    res = TEE_AllocateOperation(&op_hash, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to allocate SHA operation: 0x%x", res);
        return res;
    }

    res = TEE_DigestDoFinal(op_hash, photo_data, data_len, hash, &hash_len);
    TEE_FreeOperation(op_hash);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] SHA256 failed: 0x%x", res);
        return res;
    }

    IMSG("[RSA] Hash ready, starting RSA signing...");

    res = TEE_AllocateOperation(&op_sign, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
                                TEE_MODE_SIGN, 2048);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to allocate RSA operation: 0x%x", res);
        return res;
    }

    res = TEE_SetOperationKey(op_sign, private_key);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to set private key: 0x%x", res);
        TEE_FreeOperation(op_sign);
        return res;
    }

    res = TEE_AsymmetricSignDigest(op_sign, NULL, 0, hash, hash_len, sig, sig_len);
    TEE_FreeOperation(op_sign);

    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Signing failed: 0x%x", res);
    } else {
        IMSG("[RSA] Signing successful. Signature length: %u", *sig_len);
    }

    return res;
}


static TEE_Result create_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	uint32_t obj_data_flag;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(data, params[1].memref.buffer, data_sz);

	obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_OVERWRITE;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_sz,
					 obj_data_flag, TEE_HANDLE_NULL,
					 NULL, 0, &object);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_CreatePersistentObject failed: 0x%x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}

	res = TEE_WriteObjectData(object, data, data_sz);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_WriteObjectData failed: 0x%x", res);
		TEE_CloseAndDeletePersistentObject1(object);
	} else {
		TEE_CloseObject(object);
	}
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}

static TEE_Result read_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	
	IMSG(">>> Trying to allocate %zu bytes for read buffer", data_sz);
	IMSG(">>> Object ID: %.*s", (int)obj_id_sz, obj_id);
	IMSG(">>> Target output buffer size from REE: %zu", params[1].memref.size);
	
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_sz,
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &object);
				       
	/*
	// 特殊處理物件不存在錯誤，避免 panic
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		IMSG("[READ] Object not found: %.*s", (int)obj_id_sz, obj_id);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;  // 安全 return
	}
	
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}
	*/
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
	    IMSG("[READ] Object not found: %.*s", (int)obj_id_sz, obj_id);
	    params[1].memref.size = 0;  // 回傳 0 bytes
	    TEE_Free(obj_id);
	    TEE_Free(data);
	    return TEE_SUCCESS;         // 不傳錯誤
	}
	else if (res != TEE_SUCCESS) {
	    EMSG("TEE_OpenPersistentObject failed: 0x%x", res);
	    TEE_Free(obj_id);
	    TEE_Free(data);
	    return res;
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS)
		goto exit;

	if (object_info.dataSize > data_sz) {
		params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	res = TEE_ReadObjectData(object, data, object_info.dataSize,
				 &read_bytes);
	if (res == TEE_SUCCESS)
		TEE_MemMove(params[1].memref.buffer, data, read_bytes);

	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
		EMSG("TEE_ReadObjectData failed: 0x%x, read %u over %u",
		     res, read_bytes, object_info.dataSize);
		goto exit;
	}

	params[1].memref.size = read_bytes;

exit:
	TEE_CloseObject(object);
	TEE_Free(obj_id);
	TEE_Free(data);
	
	return res;
}

static TEE_Result write_raw_object(const char *id, const void *data, size_t size) {
    TEE_Result res;
    TEE_ObjectHandle object;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE |
                     TEE_DATA_FLAG_ACCESS_READ |
                     TEE_DATA_FLAG_OVERWRITE;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     id, strlen(id),
                                     flags,
                                     TEE_HANDLE_NULL,
                                     NULL, 0,
                                     &object);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to create object '%s': 0x%x", id, res);
        return res;
    }

    res = TEE_WriteObjectData(object, data, size);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to write object '%s': 0x%x", id, res);
    } else {
        IMSG("Successfully wrote object '%s' (%zu bytes)", id, size);
    }

    IMSG("[DEBUG] Finished writing object '%s'", id);
    TEE_CloseObject(object);
    return res;
}


static TEE_Result delete_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, obj_id, obj_id_sz,
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_ACCESS_WRITE_META,
				       &object);
	/*
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenPersistentObject (for delete) failed: 0x%x", res);
		TEE_Free(obj_id);
		return res;
	}
	*/
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
	    IMSG("[DELETE] Object not found: %.*s", (int)obj_id_sz, obj_id);
	    TEE_Free(obj_id);
	    return TEE_SUCCESS;  // ✅ 安全 return，不造成 panic
	}
	else if (res != TEE_SUCCESS) {
	    EMSG("TEE_OpenPersistentObject (for delete) failed: 0x%x", res);
	    TEE_Free(obj_id);
	    return res;
	}

	
	// add for debug
	IMSG("Deleting object ID: %.*s", (int)obj_id_sz, obj_id);

	TEE_CloseAndDeletePersistentObject1(object);
	TEE_Free(obj_id);
	return res;
}

static TEE_Result hash_photo(uint32_t param_types, TEE_Param params[4]) {
	const uint32_t expected =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,  // photo data
		                TEE_PARAM_TYPE_MEMREF_OUTPUT, // sha256 output
		                TEE_PARAM_TYPE_NONE,
		                TEE_PARAM_TYPE_NONE);

	if (param_types != expected)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint8_t hash[32];
	size_t hash_len = sizeof(hash);

	// 1. Allocate SHA256 operation
	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	// 2. Run SHA256
	res = TEE_DigestDoFinal(op,
	                        params[0].memref.buffer,
	                        params[0].memref.size,
	                        hash,
	                        &hash_len);

	TEE_FreeOperation(op);

	if (res != TEE_SUCCESS)
		return res;

	// 3. Copy result back to REE
	if (params[1].memref.size < hash_len)
		return TEE_ERROR_SHORT_BUFFER;

	TEE_MemMove(params[1].memref.buffer, hash, hash_len);
	params[1].memref.size = hash_len;

	return TEE_SUCCESS;
}

// 確保 RSA 金鑰初始化
TEE_Result TA_CreateEntryPoint(void)
{
	// return TEE_SUCCESS;
	return init_private_key();
}

// 釋放 private_key
void TA_DestroyEntryPoint(void) {
    // if (private_key != TEE_HANDLE_NULL) TEE_FreeTransientObject(private_key);
    IMSG("[TA] Entering TA_DestroyEntryPoint");
    if (private_key != TEE_HANDLE_NULL) {
        IMSG("[TA] Attempting to free private_key");
        // TEE_FreeTransientObject(private_key);  // 若還是 panic 就註解掉這行試試
    }
    IMSG("[TA] Leaving TA_DestroyEntryPoint");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[4],
				    void **session)
{
	(void)param_types;
	(void)params;
	(void)session;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	(void)session;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
				      uint32_t command,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	(void)session;
	TEE_Result res;
	
	IMSG("[TA] InvokeCommand: command = 0x%x", command);

	switch (command) {
	case TA_SECURE_STORAGE_CMD_WRITE_RAW:
		res = create_raw_object(param_types, params);
		IMSG("[TA] returning from create_raw_object, res = 0x%x", res);
		// return create_raw_object(param_types, params);
		return res;
	case TA_SECURE_STORAGE_CMD_READ_RAW:
		res = read_raw_object(param_types, params);
		IMSG("[TA] returning from read_raw_object, res = 0x%x", res);
		// return read_raw_object(param_types, params);
		return res;
	case TA_SECURE_STORAGE_CMD_DELETE:
		res = delete_object(param_types, params);
		IMSG("[TA] returning from delete_object, res = 0x%x", res);
		
		// return delete_object(param_types, params);
		return res;
	case TA_CMD_HASH_PHOTO:
		res = hash_photo(param_types, params);
		IMSG("[TA] returning from hash_photo, res = 0x%x", res);
		
		// return hash_photo(param_types, params);
		return res;
	case TA_CMD_SIGN_PHOTO:
		if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT || TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
			EMSG("[TA] Invalid param types for sign_photo");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		
		res = sign_photo(params[0].memref.buffer,
		                 params[0].memref.size,
		                 params[1].memref.buffer,
		                 &params[1].memref.size);
		IMSG("[TA] returning from sign_photo, res = 0x%x", res);
		return res;
	case TA_CMD_EXPORT_PUBKEY:
		res = export_public_key(param_types, params);
    		IMSG("[TA] returning from export_public_key, res = 0x%x", res);
    		return res;
	default:
		EMSG("[TA] Unsupported command ID: 0x%x", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}


static TEE_Result export_public_key(uint32_t param_types, TEE_Param params[4]) {
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result res;
    TEE_ObjectHandle h_mod = TEE_HANDLE_NULL, h_exp = TEE_HANDLE_NULL;
    uint8_t mod_buf[512];  // RSA 2048 最大 256 bytes，保守抓大一點
    uint8_t exp_buf[8];    // exponent 一般是 3 或 65537，最多 4 bytes，抓 8 比較保險
    uint32_t mod_len = 0, exp_len = 0;

    // 讀取 modulus
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, "rsa_modulus", 11,
                                   TEE_DATA_FLAG_ACCESS_READ, &h_mod);
    if (res != TEE_SUCCESS) {
        EMSG("[PUBKEY] Failed to open rsa_modulus: 0x%x", res);
        return res;
    }

    res = TEE_ReadObjectData(h_mod, mod_buf, sizeof(mod_buf), &mod_len);
    TEE_CloseObject(h_mod);
    if (res != TEE_SUCCESS) {
        EMSG("[PUBKEY] Failed to read rsa_modulus: 0x%x", res);
        return res;
    }

    if (params[0].memref.size < mod_len)
        return TEE_ERROR_SHORT_BUFFER;
    TEE_MemMove(params[0].memref.buffer, mod_buf, mod_len);
    params[0].memref.size = mod_len;

    // 讀取 exponent
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, "rsa_exponent", 12,
                                   TEE_DATA_FLAG_ACCESS_READ, &h_exp);
    if (res != TEE_SUCCESS) {
        EMSG("[PUBKEY] Failed to open rsa_exponent: 0x%x", res);
        return res;
    }

    res = TEE_ReadObjectData(h_exp, exp_buf, sizeof(exp_buf), &exp_len);
    TEE_CloseObject(h_exp);
    if (res != TEE_SUCCESS) {
        EMSG("[PUBKEY] Failed to read rsa_exponent: 0x%x", res);
        return res;
    }

    if (params[1].memref.size < exp_len)
        return TEE_ERROR_SHORT_BUFFER;
    TEE_MemMove(params[1].memref.buffer, exp_buf, exp_len);
    params[1].memref.size = exp_len;

    IMSG("[PUBKEY] Exported pubkey: modulus = %u bytes, exponent = %u bytes", mod_len, exp_len);
    return TEE_SUCCESS;
}


/* part 2
static TEE_Result export_public_key(uint32_t param_types, TEE_Param params[4]) {
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result res;
    TEE_ObjectHandle h_mod, h_exp;
    uint32_t read_bytes = 0;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, "rsa_modulus", 11,
                                   TEE_DATA_FLAG_ACCESS_READ, &h_mod);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to open rsa_modulus blob: 0x%x", res);
        return res;
    }

    res = TEE_ReadObjectData(h_mod, params[0].memref.buffer, params[0].memref.size, &read_bytes);
    TEE_CloseObject(h_mod);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to read rsa_modulus blob: 0x%x", res);
        return res;
    }
    params[0].memref.size = read_bytes;
    IMSG("[RSA] Read modulus blob, size = %u", read_bytes);

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, "rsa_exponent", 12,
                                   TEE_DATA_FLAG_ACCESS_READ, &h_exp);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to open rsa_exponent blob: 0x%x", res);
        return res;
    }

    res = TEE_ReadObjectData(h_exp, params[1].memref.buffer, params[1].memref.size, &read_bytes);
    TEE_CloseObject(h_exp);
    if (res != TEE_SUCCESS) {
        EMSG("[RSA] Failed to read rsa_exponent blob: 0x%x", res);
        return res;
    }
    params[1].memref.size = read_bytes;
    IMSG("[RSA] Read exponent blob, size = %u", read_bytes);

    return TEE_SUCCESS;
}
*/

/*
static TEE_Result export_public_key(uint32_t param_types, TEE_Param params[4]) {
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,  // Modulus
		TEE_PARAM_TYPE_MEMREF_OUTPUT,  // Exponent
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result res;
	uint8_t *modulus_buf = params[0].memref.buffer;
	uint32_t *modulus_len = &params[0].memref.size;
	uint8_t *exponent_buf = params[1].memref.buffer;
	uint32_t *exponent_len = &params[1].memref.size;

	// 取得 modulus
	res = TEE_GetObjectValueAttribute(private_key, TEE_ATTR_RSA_MODULUS,
	                                  modulus_buf, modulus_len);
	if (res != TEE_SUCCESS) {
		EMSG("[RSA] Failed to get modulus: 0x%x", res);
		return res;
	}

	// 取得 exponent
	res = TEE_GetObjectValueAttribute(private_key, TEE_ATTR_RSA_PUBLIC_EXPONENT,
	                                  exponent_buf, exponent_len);
	if (res != TEE_SUCCESS) {
		EMSG("[RSA] Failed to get exponent: 0x%x", res);
		return res;
	}

	IMSG("[RSA] Exported public key: modulus_len=%u, exponent_len=%u",
	     *modulus_len, *exponent_len);

	return TEE_SUCCESS;
}
*/

/*

// private_key 宣告
static TEE_ObjectHandle private_key = TEE_HANDLE_NULL;

// [Secure Storage] 初始化私鑰：若存在則讀取，否則建立並保存
static TEE_Result init_private_key(void) {private_key 宣告
    TEE_Result res;
    TEE_ObjectHandle persistent_key;

    // 嘗試讀取已存在的 RSA 私鑰
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, "rsa_key", 7,
                                   TEE_DATA_FLAG_ACCESS_READ, &persistent_key);
    if (res == TEE_SUCCESS) {
        private_key = persistent_key;
        IMSG("Loaded RSA key from secure storage");
        return TEE_SUCCESS;
    }

    // 建立暫存 RSA 金鑰物件
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 2048, &private_key);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate RSA key: 0x%x", res);
        return res;
    }

    // 產生 RSA 金鑰對（不需額外屬性）
    res = TEE_GenerateKey(private_key, 2048, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to generate RSA key: 0x%x", res);
        TEE_FreeTransientObject(private_key);
        return res;
    }

    // 保存 RSA 私鑰至 secure storage
    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, "rsa_key", 7,
                                     TEE_DATA_FLAG_ACCESS_WRITE |
                                     TEE_DATA_FLAG_ACCESS_READ |
                                     TEE_DATA_FLAG_ACCESS_WRITE_META,
                                     private_key, NULL, 0, NULL);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to store RSA key: 0x%x", res);
        TEE_FreeTransientObject(private_key);
        private_key = TEE_HANDLE_NULL;
        return res;
    }

    IMSG("Generated and saved RSA key to secure storage");
    return TEE_SUCCESS;
}

// [Photo Signing] 使用 SHA256 + RSA 簽章照片
static TEE_Result sign_photo(uint8_t *photo_data, size_t data_len,
                             uint8_t *sig, uint32_t *sig_len) {
    TEE_OperationHandle op_hash = TEE_HANDLE_NULL;
    TEE_OperationHandle op_sign = TEE_HANDLE_NULL;
    uint8_t hash[32];
    size_t hash_len = sizeof(hash);
    TEE_Result res;

    // 建立雜湊操作
    res = TEE_AllocateOperation(&op_hash, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
        return res;

    // 執行雜湊
    res = TEE_DigestDoFinal(op_hash, photo_data, data_len, hash, &hash_len);
    TEE_FreeOperation(op_hash);
    if (res != TEE_SUCCESS)
        return res;

    // 建立簽章操作
    res = TEE_AllocateOperation(&op_sign, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
                                TEE_MODE_SIGN, 2048);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_SetOperationKey(op_sign, private_key);
    if (res != TEE_SUCCESS) {
        TEE_FreeOperation(op_sign);
        return res;
    }

    // 執行簽章
    res = TEE_AsymmetricSignDigest(op_sign, NULL, 0, hash, hash_len, sig, sig_len);
    TEE_FreeOperation(op_sign);
    return res;
}

// 在 TA_DestroyEntryPoint 中釋放資源
void TA_DestroyEntryPoint(void) {
    if (private_key != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(private_key);
    }
}



// [TA Framework] 指令進入點
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    if (cmd_id != TA_CMD_PROCESS_PHOTO)
        return TEE_ERROR_NOT_SUPPORTED;

    if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    uint8_t *photo_data = params[0].memref.buffer;
    size_t photo_len = params[0].memref.size;
    uint8_t *sig_out = params[1].memref.buffer;
    uint32_t *sig_len = &params[1].memref.size;

    return sign_photo(photo_data, photo_len, sig_out, sig_len);
}

// 改動: 將初始化延後至 TA_OpenSessionEntryPoint()

// [TA Framework] 初始化金鑰（啟動時呼叫）
TEE_Result TA_CreateEntryPoint(void) {
    return init_private_key();
}

// void TA_DestroyEntryPoint(void) { if (private_key) TEE_FreeTransientObject(private_key); }

TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
                                    TEE_Param params[4], void **sessCtx) {
    (void)paramTypes;
    (void)params;
    (void)sessCtx;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sessCtx) { }
TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }

void TA_DestroyEntryPoint(void) {
	if (private_key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(private_key);
}

*/
