#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <algorithm>

using namespace std;

bitset<64> key; 		//64位密钥
bitset<48> subKeys[16];  //16个子密钥

/*
 * 初始置换IP
 */
int IP[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7 };	

/*
 * IP-1
 */		
int IP_1[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
				39, 7, 47, 15, 55, 23, 63, 31,
				38, 6, 46, 14, 54, 22, 62, 30,
				37, 5, 45, 13, 53, 21, 61, 29,
				36, 4, 44, 12, 52, 20, 60, 28,
				35, 3, 43, 11, 51, 19, 59, 27,
				34, 2, 42, 10, 50, 18, 58, 26,
				33, 1, 41, 9, 49, 17, 57, 25 };

/*
 * E-扩展规则
 */			
int E[]	= { 32, 1, 2, 3, 4, 5,
			4, 5, 6, 7, 8, 9,
			8, 9, 10, 11, 12, 13,
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25,
			24, 25, 26, 27, 28, 29,
			28, 29, 30, 31, 32, 1 };

/*
 * S盒1-8
 */
int S[8][4][16] = {
	{
		{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
		{ 0, 15, 7, 4, 15, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
		{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
		{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
	},{
		{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
		{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
		{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
		{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
	},{
		{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
		{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
		{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
		{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
	},{
		{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
		{ 12, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
		{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
		{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
	},{
		{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
		{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
		{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
		{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
	},{
		{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
		{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
		{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
		{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
	},{
		{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
		{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
		{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
		{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
	},{
		{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
		{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
		{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
		{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
	}
};

/*
 * P-置换表
 */
int P[] = { 16, 7, 20, 21,
			29, 12, 28, 17,
			1, 15, 23, 26,
			5, 18, 31, 10,
			2, 8, 24, 14,
			32, 27, 3, 9,
			19, 13, 30, 6,
			22, 11, 4, 25 };

/*
 * PC-1置换表
 */
int PC_1[] = { 57, 49, 41, 33, 25, 17, 9,
				1, 58, 50, 42, 34, 26, 18,
				10, 2, 59, 51, 43, 35, 27,
				19, 11, 3, 60, 52, 44, 36,
				63, 55, 47, 39, 31, 23, 15,
				7, 62, 54, 46, 38, 30, 22,
				14, 6, 61, 53, 45, 37, 29,
				21, 13, 5, 28, 20, 12, 4 };

/*
 * PC-2置换表
 */			
int PC_2[] = { 14, 17, 11, 24, 1, 5,
				3, 28, 15, 6, 21, 10,
				23, 19, 12, 4, 26, 8,
				16, 7, 27, 20, 13, 2,
				41, 52, 31, 37, 47, 55,
				30, 40, 51, 45, 33, 48,
				44, 49, 39, 56, 34, 53,
				46, 42, 50, 36, 29, 32 };
/*
 * 生成子密钥时每次左移位数
 */
int shiftBits[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };				

/*
 * PKMS#5填充 
 */
string padding(string src) {
	int len = src.length();
	string temp(src);
	int paddingNum = 8 - len % 8;
	if (paddingNum > 0) {
		temp.resize(len + paddingNum, paddingNum + '0');	
	}
	return temp;
}

/*
 * 8个字节的分组转换成bitset
 */
bitset<64> blockToBitset(string block) {
	bitset<64> temp;
	for (int i = 0; i < 8; ++i) {
		for (int j = 0; j < 8; ++j) {
			temp[i * 8 + j] = ((block[i] >> j) & 1);
		}
	}
	return temp;
}

string bitsetToStr(bitset<64> bits) {	
	char buf[8];
	string temp = bits.to_string();
	int j = 0;
	char h = 0;
	for (int i = 0; i < 64; ++i) {			   
        h |= temp[i] - '0';
        if((i + 1) % 8 == 0) {
            buf[j++] = h;
            h=0;
        }
        h <<= 1;	 
	}
	string str(buf, 8);
	return str;
}

/**
 *  对56位密钥的前后部分进行左移
 */
bitset<28> leftShift(bitset<28> k, int shift) {
	bitset<28> tmp = k;
	for(int i = 27; i >= 0; --i) {
		if(i - shift < 0) {
			k[i] = tmp[i - shift + 28];
		} else {
			k[i] = tmp[i - shift];
		}
	}
	return k;
}

/*
 * 生成子密钥
 */
void generateSubKeys(bitset<64> key) {
	bitset<56> tempKey;
	bitset<28> left;
	bitset<28> right;
	bitset<48> compressKey;
	//对K的56个非校验位实行置换PC-1
	for (int i = 0; i < 56; ++i) {
		tempKey[55 - i] = key[64 - PC_1[i]];
	}
	for (int i = 0; i < 16; ++i) {		
		for(int j = 28; j < 56; ++j) {
			left[j - 28] = tempKey[j];
		}
		for(int j = 0; j < 28; ++j) {
			right[j] = tempKey[j];
		}
		// 左移
		left = leftShift(left, shiftBits[i]);
		right = leftShift(right, shiftBits[i]);
		// PC-2压缩置换，由56位得到48位子密钥
		for(int j = 28; j < 56; ++j) {
			tempKey[j] = left[j - 28];
		}
		for(int j = 0; j < 28; ++j) {
			tempKey[j] = right[j];
		}
		for(int j = 0; j < 48; ++j) {
			compressKey[47-j] = tempKey[56 - PC_2[j]];
		}
		subKeys[i] = compressKey;
	}
}

/*
 * Feistel轮函数
 */
bitset<32> f(bitset<32> R, bitset<48> subKey) {
	//1. E-扩展
	bitset<48> expand;
	for (int i = 0; i < 48; ++i) {
		expand[47 - i] = R[32 - E[i]];
	} 
	//2. 与子密钥异或
	expand = expand ^ subKey;
	//3. 将2得到的结果分成8个长度为6的分组，经过8个不同的S盒进行6-4转换，得到8个长度为4的分组
	//4. 将3得到的结果顺序连接得到长度为32位的串
	bitset<32> result;	
	int x = 0;
	for (int i = 0; i < 48; i += 6) {
		int row = expand[47 - i] * 2 + expand[47 - i - 5];
		int col = expand[47 - i - 1] * 8 + expand[47 - i - 2] * 4 + expand[47 - i - 3] * 2 + expand[47 - i - 4];
		int num = S[i/6][row][col];
		bitset<4> temp(num);
		result[31 - x] = temp[3];
		result[31 - x - 1] = temp[2];
		result[31 - x - 2] = temp[1];
		result[31 - x - 3] = temp[0];		
		x += 4;
	}
	//5. 将4的结果经过P-置换，得到的结果作为输出
	bitset<32> tmp = result;
	for (int i = 0; i < 32; ++i) {
		result[31 - i] = tmp[32 - P[i]];
	}
	return result;
}

/*
 * DES加密
 */
bitset<64> encrypt(bitset<64>& plaintext) {
	bitset<64> currentText;
	bitset<32> left;
	bitset<32> right;
	bitset<32> temp;
	bitset<64> ciphertext;	
	/*
	 * 初始置换IP
	 */
	for (int i = 0; i < 64; ++i) {
		currentText[63 - i] = plaintext[64 - IP[i]];
	}

	/*
	 * L0和R0
	 */
	for (int i = 32; i < 64; ++i) {
		left[i - 32] = currentText[i];
	}	

	for (int i = 0; i < 32; ++i) {
		right[i] = currentText[i];
	}	

	/*
	 * 迭代T
	 */
	for (int i = 0; i < 16; ++i) {
		temp = right;
		right = left ^ f(right, subKeys[i]);
		left = temp;
	}

	/*
	 * 左右交换输出R16L16
	 */
	for (int i = 0; i < 32; ++i) {
		ciphertext[i] = left[i];
	}
	for (int i = 32; i < 64; ++i) {
		ciphertext[i] = right[i - 32];
	}

	/*
	 * 逆置换IP-1
	 */
	currentText = ciphertext;
	for (int i = 0; i < 64; ++i) {
		ciphertext[63 - i] = currentText[64 - IP_1[i]];
	}

	return ciphertext;
}

bitset<64> decrypt(bitset<64>& ciphertext) {
	bitset<64> plaintext;
	bitset<64> currentText;
	bitset<32> left;
	bitset<32> right;
	bitset<32> temp;
	/*
	 * 初始置换IP
	 */
	for(int i = 0; i < 64; ++i) {
		currentText[63 - i] = ciphertext[64 - IP[i]];
	}
	/*
	 * L16和R16
	 */
	for(int i = 32; i < 64; ++i) {
		left[i - 32] = currentText[i];
	}
	for(int i = 0; i < 32; ++i) {
		right[i] = currentText[i];
	}
	// 迭代,按照相反次序引用子密钥
	for(int i = 0; i < 16; ++i) {
		temp = right;
		right = left ^ f(right, subKeys[15 - i]);
		left = temp;
	}
	// L0R0
	for(int i = 0; i < 32; ++i) {
		plaintext[i] = left[i];
	}
	for(int i = 32; i < 64; ++i) {
		plaintext[i] = right[i - 32];
	}
	// IP-1置换
	currentText = plaintext;
	for(int i = 0; i < 64; ++i) {
		plaintext[63 - i] = currentText[64 - IP_1[i]];
	}
	// 返回明文
	return plaintext;
}

int main(int argc, char const *argv[]) {
	string str;
	string keyStr;	
	cout << "input the plaintext: ";
	getline(cin, str);
	int paddingNum = 8 - str.length() % 8;
	cout << "input the key: ";
	getline(cin, keyStr);
	key = blockToBitset(keyStr);	
	generateSubKeys(key);
	string plain = padding(str);
	int blockNum = plain.length() / 8;
	vector<string> blockStrs;	
	bitset<64> blocks[blockNum];
	for (int i = 0; i < blockNum; ++i) {
		string temp(plain, i * 8, 8);
		//printf("%s\n", temp.c_str());
		blockStrs.push_back(temp);		
	}	
	cout << "plaintext: " << str << endl;
	string ciphertextStr = "";
	string plaintextStr = "";
	for (int i = 0; i < blockStrs.size(); ++i) {
		blocks[i] = blockToBitset(blockStrs[i]);		
		bitset<64> ciphertext = encrypt(blocks[i]);
		ciphertextStr += bitsetToStr(ciphertext);
		bitset<64> plaintext = decrypt(ciphertext);
		string temp = bitsetToStr(plaintext);
		reverse(temp.begin(), temp.end());
		plaintextStr += temp;
	}
	string plaintextStr2 = plaintextStr.substr(0, plaintextStr.length() - paddingNum);	
	printf("ciphertext after encrypt: %s\n", ciphertextStr.c_str());
	printf("plaintext after decrypt: %s\n", plaintextStr2.c_str());
	return 0;
}

