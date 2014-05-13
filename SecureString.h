// The MIT License (MIT)
// 
// Copyright (c) 2014 Alexander Nilsson
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

/**
 * This class considers takes the following compile time parameters:
 * SECURESTRING_NOT_THREADSAFE (default: not set)
 *     Specifies wheater or not all public methods will be protected with mutexes
 * SECURESTRING_OVERRIDE_DEFAULT_ALLOCATED (default: 80)
 *     Specifies the number of characters that is pre-allocated 
 *     by the default constructor
 */

#ifndef SECURESTRING_H_INCLUDED
#define SECURESTRING_H_INCLUDED

#include <cstdlib>
#include <stdint.h>

#ifdef SECURESTRING_THREADSAFE
#include <mutex>
# define __securestring_thread_lock() std::lock_guard<std::mutex> lock(mutex_lock)
#else
# define __securestring_thread_lock()
#endif

namespace Caelus {
    namespace Utilities {

        /**
         * SecureString class, this is a container that does not keep strings in plain
         * text in memory. The contents are not encrypted, they are only obfuscated.
         * PLEASE NOTE THAT THIS IS IN NO WAY CRYTOGRAPHICALLY SECURE, IT ONLY PREVENTS
         * THE STRING FROM BEING STORED IN PLAINTEXT.
         */
        class SecureString {
        public:
            typedef uint32_t ssnr;
            typedef char ssbyte;
            typedef char* ssarr;
            typedef const char* c_ssarr;

        public:

            /**
             * Constructor:
             * Simply creates an empty string
             */
            SecureString(void);

            /**
             * Constructor:
             * Simply creates an empty string, with size chunc of pre allocated
             * memory for storage (bytes).
             * @param size - bytes of memory to be allocated
             */
            SecureString(ssnr size);

            /**
             * Constructor:
             * Creates a SecureString initialized with str as its contents.
             * OBS! This constructor performs delete on the str argument if
             * deleteStr is true.
             * @param str - The string
             * @param maxlen - The strings max length, 0 means auto
             * @param deleteStr - performs delete on str if true
             */
            SecureString(ssarr str, ssnr maxlen = 0, bool deleteStr = true, bool allowNull = false);


            /**
             * Constructor:
             * Creates a SecureString initialized with str as its contents.
             * OBS! This constructor does not perform delete on its str argument
             * due to it being 'const'
             * @param str - The string
             * @param maxlen - The strings max length, 0 means auto
             */
            SecureString(c_ssarr str, ssnr maxlen = 0);

            /** Copy-constructor **/
            SecureString(const SecureString&);

            /** Destructor **/
            ~SecureString(void);

            /**
             * This assigns a string to this string (replaces the content).
             * OBS! This method performs delete on the str argument if
             * deleteStr is true.
             * @param str - The string
             * @param maxlen - The strings max length, 0 means auto
             * @param deleteStr - performs delete on str if true
             */
            void assign(ssarr str, ssnr maxlen = 0, bool deleteStr = true, bool allowNull = false);

            /**
             * This assigns a string to this string (replaces the content).
             * OBS! This method does not perform delete on its str argument
             * due to it being 'const'
             * @param str - The string
             * @param maxlen - The strings max length, 0 means auto
             */
            void assign(c_ssarr str, ssnr maxlen = 0);

            /**
             * This assigns a string to this string (replaces the content)
             * @param str - The string to assign
             */
            void assign(const SecureString& str);

            /**
             * Assignment operator
             */
            inline SecureString&  operator= (const SecureString& other)
            {
                assign(other);
                return *this;
            }

            /**
             * This appends a string to this string.
             * OBS! This method performs delete on the str argument if
             * deleteStr is true.
             * @param str - The string
             * @param maxlen - The strings max length, 0 means auto
             * @param deleteStr - performs delete on str if true
             */
            void append(ssarr str, ssnr maxlen = 0, bool deleteStr = true);

            /**
             * This appends a string to this string.
             * OBS! This method does not perform delete on its str argument
             * due to it being 'const'
             * @param str - The string
             * @param maxlen - The strings max length, 0 means auto
             */
            void append(c_ssarr str, ssnr maxlen = 0);

            /**
             * This appends a string to this string
             * @param str - The string to append
             */
            void append(const SecureString& str);

            /**
             * This returns a pointer to a plaintext copy of the string.
             * There can only be one unsecured copy of this string at any one time,
             * multiple calls to this function will result in failure and NULL will
             * be returned.
             * When the copy is no longer needed call UnsecuredStringFinished() to
             * perform a safe delete on the string.
             * This copy is UnMutable and should thus not be modified!
             * @return pointer to an unsecured plaintext string, NULL on failure
             */
            c_ssarr getUnsecureString();

            /**
             * This returns a pointer to a plaintext copy of the string.
             * There can only be one unsecured copy of this string at any one time,
             * multiple calls to this function will result in failure and NULL will
             * be returned.
             * When the copy is no longer needed call UnsecuredStringFinished() to
             * perform a safe delete on the string.
             * This copy is Mutable and can be modified. On UnsecuredStringFinsished()
             * the modifications will be imported to the internal representation of
             * this SecureString.
             * NOTE: The string length will be equal to length() and not allocated()
             * Increasing the length by writing past the end of the buffer will result
             * in heap corruption.
             * @return pointer to an unsecured plaintext string, NULL on failure
             */
            ssarr getUnsecureStringM();

            /**
             * This returns a pointer to a plaintext copy of the string, containing
             * everything up until the next linefeed.
             * There can only be one unsecured copy of this string at any one time,
             * multiple calls to this function will result in failure and NULL will
             * be returned.
             * When the copy is no longer needed call UnsecuredStringFinished() to
             * perform a safe delete on the string.
             * This copy is UnMutable and should thus not be modified!
             * @return pointer to an unsecured plaintext string, NULL on failure
             */
            c_ssarr getUnsecureNextline();

            /**
             * This performs a safe delete on the unsecured copy of this string. If
             * the copy is mutable (see getUnsecureStringM) then any changes to the
             * copy will be imported to the internal representation of this SecureString
             */
            void UnsecuredStringFinished();

            /**
             * This returns a single character at position pos of the string.
             * @param pos - the position in the string to return
             * @return character at position pos, 0 on failure
             */
            inline ssbyte at(ssnr pos) const {
                __securestring_thread_lock();
                if (pos < length())
                    return _key[pos] ^ _data[pos];
                else
                    return 0;
            }

            /**
             * This returns the current length of the string, excluding trailing null character
             * @return length of string
             */
            inline ssnr length() const {
                __securestring_thread_lock();
                return ((ssnr)* _key) ^ _length;
            }

            /**
             * This returns the current amount of allocated bytes.
             * @return size of momory block
             */
            inline ssnr allocated() const{
                __securestring_thread_lock();
                return ((ssnr)* _key) ^ _allocated;
            }

            /**
             * This allocates a size block of memory for the string and transfers
             * the current string to the new memory block.
             * @param size
             */
            void allocate(ssnr size);

            /**
             * This resets the position of the linefeed pointer, so that
             * the next cal to getUnsecureNextline() will return the first line
             * in the string.
             */
            void resetLinefeedPosition() {
                __securestring_thread_lock();
                _nexlinefeedposition = ((ssnr)* _key) ^ 0;
            }

            /**
             * This returns true if the argument contains an equal string
             * @param s2 - the string to compare with
             * @return true - if strings are equal
             */
            bool equals(const SecureString& s2) const;

            /**
             * This returns true if the argument contains an equal string
             * @param s2 - the string to compare with
             * @return true - if strings are equal
             */
            bool equals(const char* s2) const;

            bool operator==(const SecureString& other) const
            {
                return equals(other);
            }

            /**
             * This returns true if the argument contains an equal string
             * @param s2 - the string to compare with
             * @return the corresponding checksum of the string
             */
            ssnr checksum() const{
                return _checksum;
            }

        private:
            void init();
            
            c_ssarr getUnsecureStringImpl();
            void allocateImpl(ssnr size);

        private:
            ssarr _plaintextcopy;
            ssarr _data;
            ssarr _key;
            ssnr _length;
            ssnr _allocated;
            ssnr _nexlinefeedposition;
            ssnr _checksum;
            bool _mutableplaintextcopy;

#ifdef SECURESTRING_THREADSAFE
            //only allow one thread to access this object at a time
            mutable std::mutex mutex_lock;
#endif
        };
    }
}

#endif