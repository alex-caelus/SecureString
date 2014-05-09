#include "SecureString.h"

#include <string.h>
#include <algorithm>

////////////////////////////////////////////////////////////////////////////////
//crc32 from http://web.archive.org/web/20080217222203/http://c.snippets.org/ //
////////////////////////////////////////////////////////////////////////////////
#define DWORD uint32_t
#define BYTE uint8_t

DWORD updateCRC32(unsigned char ch, DWORD crc);
DWORD crc32buf(const char *buf, size_t len);
////////////////////////////////////////////////////////////////////////////////

#ifdef SECURESTRING_OVERRIDE_DEFAULT_ALLOCATED
#define DEFAULT_ALLOCATED SECURESTRING_OVERRIDE_DEFAULT_ALLOCATED
#else
#define DEFAULT_ALLOCATED 80
#endif

using namespace Kryptan::Core;

SecureString::SecureString(void){
    init();
}

SecureString::SecureString(ssnr size){
    init();
    allocate(size);
}

SecureString::SecureString(ssarr str, ssnr maxlen, bool deleteStr){
    init();
    assign(str, maxlen, deleteStr);
}

SecureString::SecureString(c_ssarr str, ssnr maxlen){
    init();
    assign(str, maxlen);
}

SecureString::SecureString(const SecureString& src){
    init();
    assign(src);
}

SecureString::~SecureString(void)
{
    //Destroy all unsecured data
    UnsecuredStringFinished(); //is already thread safe

    __securestring_thread_lock();
    //Zero out all data
    memset(_data, 0, allocated());
    memset(_key, 0, allocated());
    _length = 0;
    _allocated = 0;

    //deallocate arrays
    delete[] _data;
    delete[] _key;
}

void SecureString::init(){
    __securestring_thread_lock();
    _data = new ssbyte[sizeof(ssnr)];
    _key = new ssbyte[sizeof(ssnr)];
    //fill key with zeros, this keeps the length() and allocated() from failing before any call to allocate(x)
    *((ssnr*)_data) = 0;
    *((ssnr*)_key) = 0;
    _length = 0;
    _allocated = 0;
    _plaintextcopy = NULL;
    _mutableplaintextcopy = false;
    resetLinefeedPosition();
}

void SecureString::allocate(ssnr size){
    __securestring_thread_lock();
    allocateImpl(size);
}

void SecureString::allocateImpl(ssnr size){
    //increase size by one to include last '\0'
    size += 1;
    //the new array must at least be able to hold a key the size of ssnr
    if (size <= sizeof(ssnr)){
        size = sizeof(ssnr)+1; //include last '\0'
    }
    //check if new size is larger than current string length
    if (size <= length()){
        size = length() + 1; //include last '\0'
    }

    //create the new arrays
    ssarr newdata = new ssbyte[size];
    ssarr newkey = new ssbyte[size];

    //store the length of the string
    ssnr strlen = length();

    //fill the key array with random data
    //and the data array as a mirror (xor equals zero)
    for (ssnr i = 0; i < size; i++){
        newkey[i] = (ssbyte)rand();
        newdata[i] = newkey[i];
    }

    //copy existing data over to the new array
    if (allocated()){
        ssnr nrOfOldAllocatedBytes = allocated();
        //After this the old key and data is zeroed out (length() and allocate() will not work)
        for (ssnr i = 0; i < nrOfOldAllocatedBytes; i++){
            newdata[i] = newkey[i] ^ (_key[i] ^ _data[i]);
            //fill old data and key with zeroes
            _data[i] = 0;
            _key[i] = 0;
        }
    }
    _length = strlen ^ ((ssnr)*newkey);
    _allocated = (size - 1) ^ ((ssnr)*newkey);

    //deallocate the old arrays
    delete[] _data;
    delete[] _key;
    _data = newdata;
    _key = newkey;
}

void SecureString::append(ssarr str, ssnr maxlen, bool deleteStr){
    __securestring_thread_lock();
    //set len to strlen(str) or maxlen, wichever is lowest (except if maxlen is 0 then set len to strlen(0))
    ssnr len = (maxlen == 0) ? strlen(str) : std::min((ssnr)strlen(str), maxlen);
    ssnr oldlen = length();
    //calculate the new total length
    ssnr totlen = oldlen + len;
    //Check if there is room for the new string
    if (totlen > allocated()){
        allocateImpl(totlen * 2); //make more room than neccessary, just in case there will be more appends later
    }
    for (ssnr i = 0; i < len; i++){
        //Store in  array
        _data[oldlen + i] = _key[oldlen + i] ^ str[i];
        //recalculate checksum
        if (oldlen == 0 && i == 0)
            _checksum = crc32buf(&(str[i]), 1);
        else
            _checksum = updateCRC32(str[i], _checksum);
    }
    _length = ((ssnr)*_key) ^ totlen;
    if (deleteStr){
        memset(str, 0, len);
        delete[] str;
    }
    resetLinefeedPosition();
}

void SecureString::append(c_ssarr str, ssnr maxlen){
    append((ssarr)str, maxlen, false);
}

void SecureString::append(const SecureString& str){
    __securestring_thread_lock();
    ssnr len = str.length();
    ssnr oldlen = this->length();
    ssnr totlen = oldlen + len;
    if (totlen > this->allocated()){
        this->allocateImpl(totlen * 2); //make more room than neccessary, just in case there will be more appends later
    }
    for (ssnr i = 0; i < len; i++){
        ssbyte c = str._data[i] ^ str._key[i];
        //Store in array
        this->_data[i + oldlen] = this->_key[oldlen + i] ^ c;
        //recalculate checksum
        if (oldlen == 0 && i == 0)
            _checksum = crc32buf(&c, 1);
        else
            _checksum = updateCRC32(c, _checksum);
    }
    _length = ((ssnr)*_key) ^ totlen;
    resetLinefeedPosition();
}

void SecureString::assign(ssarr str, ssnr maxlen, bool deleteStr){
    __securestring_thread_lock();
    //set len to strlen(str) or maxlen, wichever is lowest (except if maxlen is 0 then set len to strlen(0))
    ssnr len = (maxlen == 0) ? strlen(str) : std::min((ssnr)strlen(str), maxlen);

    //remove old data
    if (length() > 0){
        ssnr oldlen = length();
        memcpy(_data, _key, oldlen);
    }

    //allocate enough space
    if (len > allocated()){
        allocateImpl(len * 2); //make more room than neccessary, just in case there will be more appends later
    }
    for (ssnr i = 0; i < len; i++){
        _data[i] = _key[i] ^ str[i];
    }
    _data[len] = _key[len];
    _length = ((ssnr)*_key) ^ len;

    //caclulate checksum
    _checksum = crc32buf(str, len);

    if (deleteStr){
        memset(str, 0, len);
        delete[] str;
    }
    resetLinefeedPosition();
}

void SecureString::assign(c_ssarr str, ssnr maxlen){
    assign((ssarr)str, maxlen, false);
}

void SecureString::assign(const SecureString& str){
    __securestring_thread_lock();
    //remove old data
    if (length() > 0){
        ssnr oldlen = length();
        memcpy(_data, _key, oldlen);
    }

    ssnr len = str.length();
    if (len > this->allocated()){
        this->allocateImpl(len * 2); //make more room than neccessary, just in case there will be more appends later
    }
    for (ssnr i = 0; i < len; i++){
        this->_data[i] = this->_key[i] ^ (str._key[i] ^ str._data[i]);
    }
    _length = ((ssnr)*_key) ^ len;

    //checksum is already calculated by other instance, no need to do it again
    _checksum = str._checksum;

    resetLinefeedPosition();
}

SecureString::c_ssarr SecureString::getUnsecureString(){
    __securestring_thread_lock();
    return getUnsecureStringImpl();
}
SecureString::c_ssarr SecureString::getUnsecureStringImpl(){
    //there can only be one unsecure plaintext copy at a time
    if (_plaintextcopy != NULL)
        return NULL;
    ssnr size = length();
    _plaintextcopy = new ssbyte[size + 1];
    _plaintextcopy[size] = '\0';
    for (ssnr i = 0; i < size; i++){
        _plaintextcopy[i] = _key[i] ^ _data[i];
    }
    _mutableplaintextcopy = false;
    return _plaintextcopy;
}

SecureString::ssarr SecureString::getUnsecureStringM(){
    __securestring_thread_lock();
    ssarr ret = (ssarr)getUnsecureStringImpl();
    _mutableplaintextcopy = true;
    return ret;
}

SecureString::c_ssarr SecureString::getUnsecureNextline(){
    __securestring_thread_lock();
    //there can only be one unsecure plaintext copy at a time
    if (_plaintextcopy != NULL)
        return NULL;

    int startPos = (((ssnr)*_key) ^ _nexlinefeedposition);
    int tLen = ((ssnr)*_key) ^ _length;
    int sLen = 0;
    int CRLF = 0;

    //Find next linefeed
    for (int i = startPos; i < tLen; i++){
        if (at(i) == '\n'){
            sLen = i - startPos;
            break;
        }
        else if (at(i) == '\r'){
            sLen = i - startPos;
            if (at(i + 1) == '\n'){
                CRLF = 1;
            }
            break;
        }
    }

    //create new buffert
    ssarr line = new ssbyte[sLen + 1];

    //copy text over to the unsecured buffer
    for (int i = 0; i < sLen; i++){
        line[i] = _key[startPos + i] ^ _data[startPos + i];
    }
    line[sLen] = '\0';

    _nexlinefeedposition = ((ssnr)*_key) ^ (startPos + sLen + 1 + CRLF);

    //line is the plaintextcopy
    _plaintextcopy = line;
    _mutableplaintextcopy = false;
    return _plaintextcopy;
}

void SecureString::UnsecuredStringFinished(){
    __securestring_thread_lock();
    if (_plaintextcopy == NULL)
        return;
    if (_mutableplaintextcopy){
        assign(_plaintextcopy, 0, true);
    }
    else {
        memset(_plaintextcopy, 0, strlen(_plaintextcopy));
        delete[] _plaintextcopy;
    }
    _plaintextcopy = NULL;
}

bool SecureString::equals(const SecureString& s2) const{
    __securestring_thread_lock();
    if (s2.length() != this->length()){
        return false;
    }
    return _checksum == s2._checksum;
}

bool SecureString::equals(const char* s2) const{
    __securestring_thread_lock();
    unsigned int len = this->length();
    if (strlen(s2) != len){
        return false;
    }
    ssnr s2_checksum = crc32buf(s2, len);
    return _checksum == s2_checksum;
}


////////////////////////////////////////////////////////////////////////////////
//crc32 from http://web.archive.org/web/20080217222203/http://c.snippets.org/ //
////////////////////////////////////////////////////////////////////////////////
/* Crc - 32 BIT ANSI X3.66 CRC checksum files */

/* Copyright (C) 1986 Gary S. Brown.  You may use this program, or
   code or tables extracted from it, as desired without restriction.*/

#include <stdio.h>

/* Need an unsigned type capable of holding 32 bits; */

typedef DWORD UNS_32_BITS;

#define UPDC32(octet,crc) (crc_32_tab[((crc)\
    ^ ((BYTE)octet)) & 0xff] ^ ((crc) >> 8))

static UNS_32_BITS crc_32_tab[] = { /* CRC polynomial 0xedb88320 */
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

DWORD updateCRC32(unsigned char ch, DWORD crc)
{
    return ~UPDC32(ch, ~crc);
}

DWORD crc32buf(const char *buf, size_t len)
{
    register DWORD oldcrc32;

    oldcrc32 = 0xFFFFFFFF;

    for (; len; --len, ++buf)
    {
        oldcrc32 = UPDC32(*buf, oldcrc32);
    }

    return ~oldcrc32;

}
