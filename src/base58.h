// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.


//
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Doubleclicking selects the whole number as one word if it's all alphanumeric.
//
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include <string>
#include <vector>
#include "bignum.h"
#include "key.h"

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


inline std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    CAutoBN_CTX pctx;
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;

    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    std::vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum
    CBigNum bn;
    bn.setvch(vchTmp);

    // Convert bignum to std::string
    std::string str;
    // Expected size increase from base58 conversion is approximately 137%
    // use 138% to be safe
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
            throw bignum_error("EncodeBase58 : BN_div failed");
        bn = dv;
        unsigned int c = rem.getulong();
        str += pszBase58[c];
    }

    // Leading zeroes encoded as base58 zeros
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
        str += pszBase58[0];

    // Convert little endian std::string to big endian
    reverse(str.begin(), str.end());
    return str;
}

inline std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

inline bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet)
{
    CAutoBN_CTX pctx;
    vchRet.clear();
    CBigNum bn58 = 58;
    CBigNum bn = 0;
    CBigNum bnChar;
    while (isspace(*psz))
        psz++;

    // Convert big endian string to bignum
    for (const char* p = psz; *p; p++)
    {
        const char* p1 = strchr(pszBase58, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                return false;
            break;
        }
        bnChar.setulong(p1 - pszBase58);
        if (!BN_mul(&bn, &bn, &bn58, pctx))
            throw bignum_error("DecodeBase58 : BN_mul failed");
        bn += bnChar;
    }

    // Get bignum as little endian data
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == pszBase58[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return true;
}

inline bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}





inline std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

inline bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}






class CBase58Data
{
protected:
    unsigned char nVersion;
    std::vector<unsigned char> vchData;

    CBase58Data()
    {
        nVersion = 0;
        vchData.clear();
    }

    ~CBase58Data()
    {
        if (!vchData.empty())
            memset(&vchData[0], 0, vchData.size());
    }

    void SetData(int nVersionIn, const void* pdata, size_t nSize)
    {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (!vchData.empty())
            memcpy(&vchData[0], pdata, nSize);
    }

    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend)
    {
        SetData(nVersionIn, (void*)pbegin, pend - pbegin);
    }

public:
    bool SetString(const char* psz)
    {
        std::vector<unsigned char> vchTemp;
        DecodeBase58Check(psz, vchTemp);
        if (vchTemp.empty())
        {
            vchData.clear();
            nVersion = 0;
            return false;
        }
        nVersion = vchTemp[0];
        vchData.resize(vchTemp.size() - 1);
        if (!vchData.empty())
            memcpy(&vchData[0], &vchTemp[1], vchData.size());
        memset(&vchTemp[0], 0, vchTemp.size());
        return true;
    }

    bool SetString(const std::string& str)
    {
        return SetString(str.c_str());
    }

    std::string ToString() const
    {
        std::vector<unsigned char> vch(1, nVersion);
        vch.insert(vch.end(), vchData.begin(), vchData.end());
        return EncodeBase58Check(vch);
    }

    int CompareTo(const CBase58Data& b58) const
    {
        if (nVersion < b58.nVersion) return -1;
        if (nVersion > b58.nVersion) return  1;
        if (vchData < b58.vchData)   return -1;
        if (vchData > b58.vchData)   return  1;
        return 0;
    }

    bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }
};

class CBitcoinAddress : public CBase58Data
{
public:
    void SetHash160(const uint160& hash160)
    {
        SetData(fTestNet ? 111 : 0, &hash160, 20);
    }

    void SetPubKey(const std::vector<unsigned char>& vchPubKey)
    {
        SetHash160(Hash160(vchPubKey));
    }

    bool IsValid() const
    {
        int nExpectedSize = 20;
        bool fExpectTestNet = false;
        switch(nVersion)
        {
        case 0:
            break;

        case 111:
            fExpectTestNet = true;
            break;

        default:
            return false;
        }
        return fExpectTestNet == fTestNet && vchData.size() == nExpectedSize;
    }

    CBitcoinAddress()
    {
    }

    CBitcoinAddress(uint160 hash160In)
    {
        SetHash160(hash160In);
    }

    CBitcoinAddress(const std::vector<unsigned char>& vchPubKey)
    {
        SetPubKey(vchPubKey);
    }

    CBitcoinAddress(const std::string& strAddress)
    {
        SetString(strAddress);
    }

    CBitcoinAddress(const char* pszAddress)
    {
        SetString(pszAddress);
    }

    uint160 GetHash160() const
    {
        assert(vchData.size() == 20);
        uint160 hash160;
        memcpy(&hash160, &vchData[0], 20);
        return hash160;
    }
};

// THIS TEMPLATE DOESN'T BELONG HERE... but it doesn't clearly belong in any file that exists either.
// TBD where it goes.
void PBKDF2(const char P[],int Plen, const char S[], int Slen, int c,int dkLen, unsigned long* T);


class CBitcoinSecret : public CBase58Data
{
public:
    void SetSecret(const CSecret& vchSecret)
    {
        SetData(fTestNet ? 239 : 128, &vchSecret[0], vchSecret.size());
    }

    CSecret GetSecret()
    {
        CSecret vchSecret;
        vchSecret.resize(vchData.size());
        memcpy(&vchSecret[0], &vchData[0], vchData.size());
        return vchSecret;
    }

    bool IsValid() const
    {
        int nExpectedSize = 32;
        bool fExpectTestNet = false;
        switch(nVersion)
        {
        case 128:
            break;

        case 239:
            fExpectTestNet = true;
            break;

        default:
            return false;
        }
        return fExpectTestNet == fTestNet && vchData.size() == nExpectedSize;
    }

    CBitcoinSecret(const CSecret& vchSecret)
    {
        SetSecret(vchSecret);
    }

    CBitcoinSecret()
    {
    }

    bool SetString(const std::string& strAddress) 
    {
        return SetString(strAddress.c_str());
    }


    bool SetString(const char *psz)	
    {
        int nSecretLength = strlen(psz);
        if (nSecretLength == 22 || nSecretLength == 26)
        {
            if (psz[0] == 'S')
            {
                int i;
                bool fMini = false;
                for (i = 0; i < nSecretLength; i++)
                {
                    char c = psz[i];
                    if (c < '1' || c > 'z') break;
                    if (c > '9' && c < 'A') break;
                    if (c > 'Z' && c < 'a') break;
                    if (c == 'I' || c == 'l' || c == 'O') break;
                }
                if (i==nSecretLength)
                {
                    std::string strKeycheck(psz);
                    strKeycheck += "?";
                    uint256 hash;
                    SHA256((unsigned char*)strKeycheck.c_str(), strKeycheck.size(), (unsigned char*)&hash);					
                    if (*(hash.begin()) == 0) 
                    {
                        uint256 hash;
                        SHA256((unsigned char*)psz, nSecretLength, (unsigned char*)&hash);
                        SetData(fTestNet ? 239 : 128, &hash, 32);
                        return true;
                    }
                    else if (*(hash.begin()) == 1)
                    {
                        int nIterations = 1;
                        const int nIterationChoices = 81;
                        int allowedIterations[nIterationChoices] = {1,1,1,2,2,2,3,3,4,5,6,7,8,10,11,13,16,19,23,27,32,38,45,54,64,76,
                            91,108,128,152,181,215,256,304,362,431,512,609,724,861,1024,1218,1448,1722,2048,2435,
                            2896,3444,4096,4871,5793,6889,8192,9742,11585,13777,16384,19484,23170,27554,32768,38968,
                            46341,55109,65536,77936,92682,110218,131072,155872,185364,220436,262144,311744,370728,
                            440872,524288,623487,741455,881744,1048576};

                        unsigned char idx = hash.begin()[1];
                        
                        if (idx >= nIterationChoices) return false;
                        nIterations = allowedIterations[idx];

                        unsigned long T[512];
                        memset(&T, 0, sizeof(T));
                        PBKDF2(psz, nSecretLength, "Satoshi Nakamoto", 16, nIterations, 32, T);
                        // guarantee correct endianness

                        unsigned char key[32];						
                        for (int i=0,keyidx=0; i<8; i++) {
                            key[keyidx++]=(T[i]>>24) & 0xff;
                            key[keyidx++]=(T[i]>>16) & 0xff;
                            key[keyidx++]=(T[i]>>8) & 0xff;
                            key[keyidx++]=(T[i]) & 0xff;
                        }

                        SetData(fTestNet ? 239 : 128, key, 32);
                        return true;
                    }
                }
            }
        }
        return CBase58Data::SetString(psz);

    }


};

#endif
