#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <queue>
#include <algorithm>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "dlex.h"
#include "mbedtls/md5.h"

using namespace std;

/**
  * 语法分析器
  *
  */
class lexcion {
	private:
	static uint32_t crc(const void *cp, uint16_t length);
	static uint8_t attributes(uint8_t id);
	static uint8_t methods(uint8_t id);
	static bool rights(uint8_t index, queue<string> &t, union __cosem_entry_file &e);
	static bool significance(uint8_t index, queue<string> &t, union __cosem_entry_file &e);
	static bool comp(union __cosem_entry_file &a, union __cosem_entry_file &b);
	uint64_t version;
	vector<union __cosem_entry_file> list;

	public:
	bool start();
	bool append(vector<string> &v);
	bool finish();
};

/**
  * crc32 确保与 VirtualMeter 中算法保持一致
  *
  */
uint32_t lexcion::crc(const void *cp, uint16_t length) {
	static const uint32_t crc32tab[256] = {
	0x00000000,	   0x04c11db7,	  0x09823b6e,	 0x0d4326d9,
	0x130476dc,	   0x17c56b6b,	  0x1a864db2,	 0x1e475005,
	0x2608edb8,	   0x22c9f00f,	  0x2f8ad6d6,	 0x2b4bcb61,
	0x350c9b64,	   0x31cd86d3,	  0x3c8ea00a,	 0x384fbdbd,
	0x4c11db70,	   0x48d0c6c7,	  0x4593e01e,	 0x4152fda9,
	0x5f15adac,	   0x5bd4b01b,	  0x569796c2,	 0x52568b75,
	0x6a1936c8,	   0x6ed82b7f,	  0x639b0da6,	 0x675a1011,
	0x791d4014,	   0x7ddc5da3,	  0x709f7b7a,	 0x745e66cd,
	0x9823b6e0,	   0x9ce2ab57,	  0x91a18d8e,	 0x95609039,
	0x8b27c03c,	   0x8fe6dd8b,	  0x82a5fb52,	 0x8664e6e5,
	0xbe2b5b58,	   0xbaea46ef,	  0xb7a96036,	 0xb3687d81,
	0xad2f2d84,	   0xa9ee3033,	  0xa4ad16ea,	 0xa06c0b5d,
	0xd4326d90,	   0xd0f37027,	  0xddb056fe,	 0xd9714b49,
	0xc7361b4c,	   0xc3f706fb,	  0xceb42022,	 0xca753d95,
	0xf23a8028,	   0xf6fb9d9f,	  0xfbb8bb46,	 0xff79a6f1,
	0xe13ef6f4,	   0xe5ffeb43,	  0xe8bccd9a,	 0xec7dd02d,
	0x34867077,	   0x30476dc0,	  0x3d044b19,	 0x39c556ae,
	0x278206ab,	   0x23431b1c,	  0x2e003dc5,	 0x2ac12072,
	0x128e9dcf,	   0x164f8078,	  0x1b0ca6a1,	 0x1fcdbb16,
	0x018aeb13,	   0x054bf6a4,	  0x0808d07d,	 0x0cc9cdca,
	0x7897ab07,	   0x7c56b6b0,	  0x71159069,	 0x75d48dde,
	0x6b93dddb,	   0x6f52c06c,	  0x6211e6b5,	 0x66d0fb02,
	0x5e9f46bf,	   0x5a5e5b08,	  0x571d7dd1,	 0x53dc6066,
	0x4d9b3063,	   0x495a2dd4,	  0x44190b0d,	 0x40d816ba,
	0xaca5c697,	   0xa864db20,	  0xa527fdf9,	 0xa1e6e04e,
	0xbfa1b04b,	   0xbb60adfc,	  0xb6238b25,	 0xb2e29692,
	0x8aad2b2f,	   0x8e6c3698,	  0x832f1041,	 0x87ee0df6,
	0x99a95df3,	   0x9d684044,	  0x902b669d,	 0x94ea7b2a,
	0xe0b41de7,	   0xe4750050,	  0xe9362689,	 0xedf73b3e,
	0xf3b06b3b,	   0xf771768c,	  0xfa325055,	 0xfef34de2,
	0xc6bcf05f,	   0xc27dede8,	  0xcf3ecb31,	 0xcbffd686,
	0xd5b88683,	   0xd1799b34,	  0xdc3abded,	 0xd8fba05a,
	0x690ce0ee,	   0x6dcdfd59,	  0x608edb80,	 0x644fc637,
	0x7a089632,	   0x7ec98b85,	  0x738aad5c,	 0x774bb0eb,
	0x4f040d56,	   0x4bc510e1,	  0x46863638,	 0x42472b8f,
	0x5c007b8a,	   0x58c1663d,	  0x558240e4,	 0x51435d53,
	0x251d3b9e,	   0x21dc2629,	  0x2c9f00f0,	 0x285e1d47,
	0x36194d42,	   0x32d850f5,	  0x3f9b762c,	 0x3b5a6b9b,
	0x0315d626,	   0x07d4cb91,	  0x0a97ed48,	 0x0e56f0ff,
	0x1011a0fa,	   0x14d0bd4d,	  0x19939b94,	 0x1d528623,
	0xf12f560e,	   0xf5ee4bb9,	  0xf8ad6d60,	 0xfc6c70d7,
	0xe22b20d2,	   0xe6ea3d65,	  0xeba91bbc,	 0xef68060b,
	0xd727bbb6,	   0xd3e6a601,	  0xdea580d8,	 0xda649d6f,
	0xc423cd6a,	   0xc0e2d0dd,	  0xcda1f604,	 0xc960ebb3,
	0xbd3e8d7e,	   0xb9ff90c9,	  0xb4bcb610,	 0xb07daba7,
	0xae3afba2,	   0xaafbe615,	  0xa7b8c0cc,	 0xa379dd7b,
	0x9b3660c6,	   0x9ff77d71,	  0x92b45ba8,	 0x9675461f,
	0x8832161a,	   0x8cf30bad,	  0x81b02d74,	 0x857130c3,
	0x5d8a9099,	   0x594b8d2e,	  0x5408abf7,	 0x50c9b640,
	0x4e8ee645,	   0x4a4ffbf2,	  0x470cdd2b,	 0x43cdc09c,
	0x7b827d21,	   0x7f436096,	  0x7200464f,	 0x76c15bf8,
	0x68860bfd,	   0x6c47164a,	  0x61043093,	 0x65c52d24,
	0x119b4be9,	   0x155a565e,	  0x18197087,	 0x1cd86d30,
	0x029f3d35,	   0x065e2082,	  0x0b1d065b,	 0x0fdc1bec,
	0x3793a651,	   0x3352bbe6,	  0x3e119d3f,	 0x3ad08088,
	0x2497d08d,	   0x2056cd3a,	  0x2d15ebe3,	 0x29d4f654,
	0xc5a92679,	   0xc1683bce,	  0xcc2b1d17,	 0xc8ea00a0,
	0xd6ad50a5,	   0xd26c4d12,	  0xdf2f6bcb,	 0xdbee767c,
	0xe3a1cbc1,	   0xe760d676,	  0xea23f0af,	 0xeee2ed18,
	0xf0a5bd1d,	   0xf464a0aa,	  0xf9278673,	 0xfde69bc4,
	0x89b8fd09,	   0x8d79e0be,	  0x803ac667,	 0x84fbdbd0,
	0x9abc8bd5,	   0x9e7d9662,	  0x933eb0bb,	 0x97ffad0c,
	0xafb010b1,	   0xab710d06,	  0xa6322bdf,	 0xa2f33668,
	0xbcb4666d,	   0xb8757bda,	  0xb5365d03,	 0xb1f740b4
	};
	uint16_t cnt;
	uint32_t val = 0;
	const uint8_t *p = (const uint8_t *)cp;

	if(!p){
		return 0;
	}

	for(cnt=0; cnt<length; cnt++){
		val = (val << 8) ^ crc32tab[(val >> 24) ^ p[cnt]];
	}

	return val;
}

/**
  * 获取指定类的 属性 数量
  *
  */
uint8_t lexcion::attributes(uint8_t id) {
	switch(id) {
		case CLASS_DATA: return(2);
		case CLASS_REGISTER: return(3);
		case CLASS_EXTREGISTER: return(5);
		case CLASS_DEMANDREGISTER: return(9);
		case CLASS_PROFILE: return(8);
		case CLASS_CLOCK: return(9);
		case CLASS_SCRIPT: return(2);
		case CLASS_SCHEDULE: return(2);
		case CLASS_SPECIALDAY: return(2);
		case CLASS_ASSOCIATION_LN: return(11);
		case CLASS_SAP: return(2);
		case CLASS_IMAGE_TRANSFER: return(7);
		case CLASS_ACTIVITYCALENDER: return(10);
		case CLASS_REGISTER_MONITOR: return(4);
		case CLASS_SINGLE_ACTION: return(4);
		case CLASS_HDLC_SETUP: return(9);
		case CLASS_MAC_ADDRESS_SETUP: return(2);
		case CLASS_RELAY: return(4);
		case CLASS_LIMITER: return(11);
	}

	return(0);
}

/**
  * 获取指定类的 方法 数量
  *
  */
uint8_t lexcion::methods(uint8_t id) {
	switch(id) {
		case CLASS_DATA: return(0);
		case CLASS_REGISTER: return(1);
		case CLASS_EXTREGISTER: return(1);
		case CLASS_DEMANDREGISTER: return(2);
		case CLASS_PROFILE: return(2);
		case CLASS_CLOCK: return(6);
		case CLASS_SCRIPT: return(1);
		case CLASS_SCHEDULE: return(3);
		case CLASS_SPECIALDAY: return(2);
		case CLASS_ASSOCIATION_LN: return(6);
		case CLASS_SAP: return(1);
		case CLASS_IMAGE_TRANSFER: return(4);
		case CLASS_ACTIVITYCALENDER: return(1);
		case CLASS_REGISTER_MONITOR: return(0);
		case CLASS_SINGLE_ACTION: return(0);
		case CLASS_HDLC_SETUP: return(0);
		case CLASS_MAC_ADDRESS_SETUP: return(0);
		case CLASS_RELAY: return(2);
		case CLASS_LIMITER: return(0);
	}

	return(0);
}

/**
  * 解析 权限
  *
  */
bool lexcion::rights(uint8_t index, queue<string> &t, union __cosem_entry_file &e) {
	if(((e.key >> 56) & 0xff) > 8) {
		if(index >= 24) {
			return(false);
		}
	}
	else {
		if(index >= 16) {
			return(false);
		}
	}

	if(t.front().find("ATTR_") != t.front().npos) {
		if(t.front().find("METHOD_") != t.front().npos) {
			return(false);
		}

		if(((e.key >> 56) & 0xff) > 8) {
			e.high.entry.right[index][0] = 0;
			e.high.entry.right[index][1] = 0;
			e.high.entry.right[index][2] = 0;
			for(uint8_t cnt=0; cnt<3; cnt++) {
				if(t.front().find("ATTR_READ") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x01;
				}
				if(t.front().find("ATTR_WRITE") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x02;
				}
				if(t.front().find("ATTR_AUTHREQ") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x04;
				}
				if(t.front().find("ATTR_ENCREQ") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x08;
				}
				if(t.front().find("ATTR_DIGITREQ") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x10;
				}
				if(t.front().find("ATTR_AUTHRSP") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x20;
				}
				if(t.front().find("ATTR_ENCRSP") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x40;
				}
				if(t.front().find("ATTR_DIGITRSP") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x80;
				}

				t.pop();
			}
		}
		else {
			e.low.entry.right[index][0] = 0;
			e.low.entry.right[index][1] = 0;
			e.low.entry.right[index][2] = 0;
			for(uint8_t cnt=0; cnt<3; cnt++) {
				if(t.front().find("ATTR_READ") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x01;
				}
				if(t.front().find("ATTR_WRITE") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x02;
				}
				if(t.front().find("ATTR_AUTHREQ") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x04;
				}
				if(t.front().find("ATTR_ENCREQ") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x08;
				}
				if(t.front().find("ATTR_DIGITREQ") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x10;
				}
				if(t.front().find("ATTR_AUTHRSP") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x20;
				}
				if(t.front().find("ATTR_ENCRSP") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x40;
				}
				if(t.front().find("ATTR_DIGITRSP") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x80;
				}

				t.pop();
			}

			if(lexcion::significance(index, t, e) != true) {
				return(false);
			}
		}
	}
	else if(t.front().find("METHOD_") != t.front().npos) {
		if(t.front().find("ATTR_") != t.front().npos) {
			return(false);
		}

		if(((e.key >> 56) & 0xff) > 8) {
			e.high.entry.right[index][0] = 0;
			e.high.entry.right[index][1] = 0;
			e.high.entry.right[index][2] = 0;
			for(uint8_t cnt=0; cnt<3; cnt++) {
				if(t.front().find("METHOD_ACCESS") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x01;
				}
				if(t.front().find("METHOD_AUTHREQ") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x04;
				}
				if(t.front().find("METHOD_ENCREQ") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x08;
				}
				if(t.front().find("METHOD_DIGITREQ") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x10;
				}
				if(t.front().find("METHOD_AUTHRSP") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x20;
				}
				if(t.front().find("METHOD_ENCRSP") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x40;
				}
				if(t.front().find("METHOD_DIGITRSP") != t.front().npos) {
					e.high.entry.right[index][cnt] |= 0x80;
				}

				t.pop();
			}
		}
		else {
			e.low.entry.right[index][0] = 0;
			e.low.entry.right[index][1] = 0;
			e.low.entry.right[index][2] = 0;
			for(uint8_t cnt=0; cnt<3; cnt++) {
				if(t.front().find("METHOD_ACCESS") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x01;
				}
				if(t.front().find("METHOD_AUTHREQ") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x04;
				}
				if(t.front().find("METHOD_ENCREQ") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x08;
				}
				if(t.front().find("METHOD_DIGITREQ") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x10;
				}
				if(t.front().find("METHOD_AUTHRSP") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x20;
				}
				if(t.front().find("METHOD_ENCRSP") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x40;
				}
				if(t.front().find("METHOD_DIGITRSP") != t.front().npos) {
					e.low.entry.right[index][cnt] |= 0x80;
				}

				t.pop();
			}
		}
	}
	else {
		return(false);
	}

	return(true);
}

/**
  * 解析 物理意义
  *
  */
bool lexcion::significance(uint8_t index, queue<string> &t, union __cosem_entry_file &e) {
	uint32_t val = 0;
	uint32_t *mid = NULL;
	uint32_t attr = index + 1;
	stringstream out;

	switch((e.key >> 56) & 0xff) {
		case CLASS_DATA: {
			if(attr == 2) {
				mid = &e.low.entry.mid[0];
			}
			else {
				return(true);
			}
			break;
		}
		case CLASS_REGISTER: {
			if(attr == 2) {
				mid = &e.low.entry.mid[0];
			}
			else if(attr == 3) {
				mid = &e.low.entry.mid[1];
			}
			else {
				return(true);
			}
			break;
		}
		case CLASS_EXTREGISTER: {
			if(attr == 2) {
				mid = &e.low.entry.mid[0];
			}
			else if(attr == 3) {
				mid = &e.low.entry.mid[1];
			}
			else if(attr == 5) {
				mid = &e.low.entry.mid[2];
			}
			else {
				return(true);
			}
			break;
		}
		case CLASS_DEMANDREGISTER: {
			if(attr == 2) {
				mid = &e.low.entry.mid[0];
			}
			else if(attr == 3) {
				mid = &e.low.entry.mid[1];
			}
			else if(attr == 4) {
				mid = &e.low.entry.mid[2];
			}
			else {
				return(true);
			}
			break;
		}
		case CLASS_PROFILE: {
			if(attr == 4) {
				mid = &e.low.entry.mid[0];
			}
			else if(attr == 7) {
				mid = &e.low.entry.mid[1];
			}
			else if(attr == 8) {
				mid = &e.low.entry.mid[2];
			}
			else {
				return(true);
			}
			break;
		}
		case CLASS_CLOCK: {
			if(attr == 2) {
				mid = &e.low.entry.mid[0];
			}
			else if(attr == 3) {
				mid = &e.low.entry.mid[1];
			}
			else {
				return(true);
			}
			break;
		}
	}

	if(mid == NULL) {
		return(true);
	}

	for(uint8_t cnt = 0; cnt < 6; cnt++) {
		if(t.empty()) {
			break;
		}

		if(cnt == 0) {
			if(t.front().find("NULL") != t.front().npos) {
				val |= (M_NULL<<27);
			}
			else if(t.front().find("P_ENERGY") != t.front().npos) {
				val |= (M_P_ENERGY<<27);
			}
			else if(t.front().find("Q_ENERGY") != t.front().npos) {
				val |= (M_Q_ENERGY<<27);
			}
			else if(t.front().find("S_ENERGY") != t.front().npos) {
				val |= (M_S_ENERGY<<27);
			}
			else if(t.front().find("P_POWER") != t.front().npos) {
				val |= (M_P_POWER<<27);
			}
			else if(t.front().find("Q_POWER") != t.front().npos) {
				val |= (M_Q_POWER<<27);
			}
			else if(t.front().find("S_POWER") != t.front().npos) {
				val |= (M_S_POWER<<27);
			}
			else if(t.front().find("VOLTAGE") != t.front().npos) {
				val |= (M_VOLTAGE<<27);
			}
			else if(t.front().find("CURRENT") != t.front().npos) {
				val |= (M_CURRENT<<27);
			}
			else if(t.front().find("POWER_FACTOR") != t.front().npos) {
				val |= (M_POWER_FACTOR<<27);
			}
			else if(t.front().find("ANGLE") != t.front().npos) {
				val |= (M_ANGLE<<27);
			}
			else if(t.front().find("FREQUENCY") != t.front().npos) {
				val |= (M_FREQUENCY<<27);
			}
			else if(t.front().find("BIN") != t.front().npos) {
				val |= (FMT_BIN<<27);
			}
			else if(t.front().find("HEX") != t.front().npos) {
				val |= (FMT_HEX<<27);
			}
			else if(t.front().find("DATE") != t.front().npos) {
				val |= (FMT_DATE<<27);
			}
			else if(t.front().find("TIME") != t.front().npos) {
				val |= (FMT_TIME<<27);
			}
			else if(t.front().find("DTIME") != t.front().npos) {
				val |= (FMT_DTIME<<27);
			}
			else if(t.front().find("BCD") != t.front().npos) {
				val |= (FMT_BCD<<27);
			}
			else if(t.front().find("ASCII") != t.front().npos) {
				val |= (FMT_ASCII<<27);
			}
			else if(t.front().find("STR") != t.front().npos) {
				val |= (FMT_STR<<27);
			}
			else {
				cout << "Item can't be recognized."<< endl;
				return(false);
			}
		}
		else if(cnt == 1) {
			if(t.front().find("PHASE_N") != t.front().npos) {
				val |= (M_PHASE_N<<24);
			}
			else if(t.front().find("PHASE_A") != t.front().npos) {
				val |= (M_PHASE_A<<24);
			}
			else if(t.front().find("PHASE_B") != t.front().npos) {
				val |= (M_PHASE_B<<24);
			}
			else if(t.front().find("PHASE_C") != t.front().npos) {
				val |= (M_PHASE_C<<24);
			}
			else if(t.front().find("PHASE_AB") != t.front().npos) {
				val |= (M_PHASE_AB<<24);
			}
			else if(t.front().find("PHASE_AC") != t.front().npos) {
				val |= (M_PHASE_AC<<24);
			}
			else if(t.front().find("PHASE_BC") != t.front().npos) {
				val |= (M_PHASE_BC<<24);
			}
			else if(t.front().find("PHASE_T") != t.front().npos) {
				val |= (M_PHASE_T<<24);
			}
			else {
				cout << "Phase can't be recognized."<< endl;
				return(false);
			}
		}
		else if(cnt == 2) {
			unsigned int c;
			out.clear();
			out << t.front();
			out >> c;
			if(c > 15) {
				cout << "Rate can't be recognized."<< endl;
				return(false);
			}
			else {
				val |= (c<<20);
			}
		}
		else if(cnt == 3) {
			if(t.front().find("SCALE_N8") != t.front().npos) {
				val |= (M_SCALE_N8<<15);
			}
			else if(t.front().find("SCALE_N7") != t.front().npos) {
				val |= (M_SCALE_N7<<15);
			}
			else if(t.front().find("SCALE_N6") != t.front().npos) {
				val |= (M_SCALE_N6<<15);
			}
			else if(t.front().find("SCALE_N5") != t.front().npos) {
				val |= (M_SCALE_N5<<15);
			}
			else if(t.front().find("SCALE_N4") != t.front().npos) {
				val |= (M_SCALE_N4<<15);
			}
			else if(t.front().find("SCALE_N3") != t.front().npos) {
				val |= (M_SCALE_N3<<15);
			}
			else if(t.front().find("SCALE_N2") != t.front().npos) {
				val |= (M_SCALE_N2<<15);
			}
			else if(t.front().find("SCALE_N1") != t.front().npos) {
				val |= (M_SCALE_N1<<15);
			}
			else if(t.front().find("SCALE_ZN") != t.front().npos) {
				val |= (M_SCALE_ZN<<15);
			}
			else if(t.front().find("SCALE_ZP") != t.front().npos) {
				val |= (M_SCALE_ZP<<15);
			}
			else if(t.front().find("SCALE_P1") != t.front().npos) {
				val |= (M_SCALE_P1<<15);
			}
			else if(t.front().find("SCALE_P2") != t.front().npos) {
				val |= (M_SCALE_P2<<15);
			}
			else if(t.front().find("SCALE_P3") != t.front().npos) {
				val |= (M_SCALE_P3<<15);
			}
			else if(t.front().find("SCALE_P4") != t.front().npos) {
				val |= (M_SCALE_P4<<15);
			}
			else if(t.front().find("SCALE_P5") != t.front().npos) {
				val |= (M_SCALE_P5<<15);
			}
			else if(t.front().find("SCALE_P6") != t.front().npos) {
				val |= (M_SCALE_P6<<15);
			}
			else if(t.front().find("SCALE_P7") != t.front().npos) {
				val |= (M_SCALE_P7<<15);
			}
			else if(t.front().find("SCALE_P8") != t.front().npos) {
				val |= (M_SCALE_P8<<15);
			}
			else {
				cout << "Scale can't be recognized."<< endl;
				return(false);
			}
		}
		else if(cnt == 4) {
			if(t.front().find("NULL") != t.front().npos) {
				val |= (AXDR_NULL<<10);
			}
			else if(t.front().find("ARRAY") != t.front().npos) {
				val |= (AXDR_ARRAY<<10);
			}
			else if(t.front().find("STRUCTURE") != t.front().npos) {
				val |= (AXDR_STRUCTURE<<10);
			}
			else if(t.front().find("BOOLEAN") != t.front().npos) {
				val |= (AXDR_BOOLEAN<<10);
			}
			else if(t.front().find("BIT_STRING") != t.front().npos) {
				val |= (AXDR_BIT_STRING<<10);
			}
			else if(t.front().find("DOUBLE_LONG") != t.front().npos) {
				val |= (AXDR_DOUBLE_LONG<<10);
			}
			else if(t.front().find("DOUBLE_LONG_UNSIGNED") != t.front().npos) {
				val |= (AXDR_DOUBLE_LONG_UNSIGNED<<10);
			}
			else if(t.front().find("OCTET_STRING") != t.front().npos) {
				val |= (AXDR_OCTET_STRING<<10);
			}
			else if(t.front().find("VISIBLE_STRING") != t.front().npos) {
				val |= (AXDR_VISIBLE_STRING<<10);
			}
			else if(t.front().find("UTF8_STRING") != t.front().npos) {
				val |= (AXDR_UTF8_STRING<<10);
			}
			else if(t.front().find("BCD") != t.front().npos) {
				val |= (AXDR_BCD<<10);
			}
			else if(t.front().find("INTEGER") != t.front().npos) {
				val |= (AXDR_INTEGER<<10);
			}
			else if(t.front().find("LONG") != t.front().npos) {
				val |= (AXDR_LONG<<10);
			}
			else if(t.front().find("UNSIGNED") != t.front().npos) {
				val |= (AXDR_UNSIGNED<<10);
			}
			else if(t.front().find("LONG_UNSIGNED") != t.front().npos) {
				val |= (AXDR_LONG_UNSIGNED<<10);
			}
			else if(t.front().find("COMPACT_ARRAY") != t.front().npos) {
				val |= (AXDR_COMPACT_ARRAY<<10);
			}
			else if(t.front().find("LONG64") != t.front().npos) {
				val |= (AXDR_LONG64<<10);
			}
			else if(t.front().find("LONG64_UNSIGNED") != t.front().npos) {
				val |= (AXDR_LONG64_UNSIGNED<<10);
			}
			else if(t.front().find("ENUM") != t.front().npos) {
				val |= (AXDR_ENUM<<10);
			}
			else if(t.front().find("FLOAT32") != t.front().npos) {
				val |= (AXDR_FLOAT32<<10);
			}
			else if(t.front().find("FLOAT64") != t.front().npos) {
				val |= (AXDR_FLOAT64<<10);
			}
			else if(t.front().find("DATE_TIME") != t.front().npos) {
				val |= (AXDR_DATE_TIME<<10);
			}
			else if(t.front().find("DATE") != t.front().npos) {
				val |= (AXDR_DATE<<10);
			}
			else if(t.front().find("TIME") != t.front().npos) {
				val |= (AXDR_TIME<<10);
			}
			else {
				cout << "Type can't be recognized."<< endl;
				return(false);
			}
		}
		else if(cnt == 5) {
			bool is_quad = false;
			if(t.front().find("QUAD_I") != t.front().npos) {
				val |= (M_QUAD_I<<0); is_quad = true;
			}
			if(t.front().find("QUAD_II") != t.front().npos) {
				val |= (M_QUAD_II<<0); is_quad = true;
			}
			if(t.front().find("QUAD_III") != t.front().npos) {
				val |= (M_QUAD_III<<0); is_quad = true;
			}
			if(t.front().find("QUAD_V") != t.front().npos) {
				val |= (M_QUAD_V<<0); is_quad = true;
			}
			if(t.front().find("QUAD_NI") != t.front().npos) {
				val |= (M_QUAD_NI<<0); is_quad = true;
			}
			if(t.front().find("QUAD_NII") != t.front().npos) {
				val |= (M_QUAD_NII<<0); is_quad = true;
			}
			if(t.front().find("QUAD_NIII") != t.front().npos) {
				val |= (M_QUAD_NIII<<0); is_quad = true;
			}
			if(t.front().find("QUAD_NV") != t.front().npos) {
				val |= (M_QUAD_NV<<0); is_quad = true;
			}

			if(!is_quad) {
				long c;
				out.clear();
				out << t.front();
				out >> c;
				if((c < 0) || (c > 1023)) {
					cout << "Flexable overflow."<< endl;
					return(false);
				}
				else {
					val |= c;
				}
			}
		}

		t.pop();
	}

	*mid = val;

	return(true);
}
/**
  * 排序比较器
  *
  */
bool lexcion::comp(union __cosem_entry_file &a, union __cosem_entry_file &b) {
	return((a.key < b.key));
}

/**
  * 启动语法分析器
  *
  */
bool lexcion::start() {
	this->version = 0;
	this->list.clear();
	return(true);
}

/**
  * 向语法分析器添加一个包
  *
  */
bool lexcion::append(vector<string> &v) {
	union __cosem_entry_file entry;
	bool havever = false;
	bool isver = false;
	uint8_t attribute;
	uint8_t method;
	stringstream out;

	memset(reinterpret_cast<char *>(&entry), 0, sizeof(entry));

	//遍历两个花括号之间的所有字符串，以空格为分隔符
	for(vector<string>::iterator iter = v.begin(); iter != v.end(); iter++) {
		queue<string> token;
		istringstream in(*iter);
		string str;

		//遍历一行内所有的项
		while(in>>str) {
			if(!str.empty()) {
				str.erase(0,str.find_first_not_of(" "));
			}
			if(!str.empty()) {
				str.erase(str.find_last_not_of(" ") + 1);
			}
			token.push(str);
		}
		//行解析
		//第一行，解析 version 或者 class 和 obis
		if((iter - v.begin()) == 0) {
			if(token.size() < 2) {
				cout << "Too less element in this line :"<< *iter << "." << endl;
				return(false);
			}

			token.pop();

			if(token.front() == "version") {
				if(havever == true) {
					cout << "Version duplicate :"<< *iter << "." << endl;
					return(false);
				}

				isver = true;
			}
			else if(token.size() < 7) {
				cout << "Too less element in this line :"<< *iter << "." << endl;
				return(false);
			}
			else {
				for (uint16_t cnt = 0; cnt < 7; cnt++) {
					long c;
					out.clear();
					out << token.front();
					out >> c;
					if((c < 0) || (c > 255)) {
						cout << "Number overflow :"<< *iter << "." << endl;
						return(false);
					}
					else {
						entry.key += c;
						entry.key <<= 8;
					}

					token.pop();
				}

				attribute = lexcion::attributes((entry.key >> 56) & 0xff);
				method = lexcion::methods((entry.key >> 56) & 0xff);

				if((attribute + method) == 0) {
					cout << "This class have no attribute and method :"<< *iter << "." << endl;
					return(false);
				}
			}
		}
		//第二行，解析 version 或者 suit
		else if((iter - v.begin()) == 1) {
			if(isver == true) {
				long long c;
				out.clear();
				out << token.front();
				out >> c;
				if(c < 0) {
					cout << "Number overflow :"<< *iter << "." << endl;
					return(false);
				}
				else {
					this->version = c;
					havever = true;
				}
			}
			else {
				uint16_t size = token.size();
				for (uint16_t cnt = 0; cnt < size; cnt++) {
					long c;
					out.clear();
					out << token.front();
					out >> c;
					if((c < 1) || (c > 8)) {
						cout << "Number overflow :"<< *iter << "." << endl;
						return(false);
					}
					else {
						entry.key |= (1 << (c-1));
					}

					token.pop();
				}
			}
		}
		//第三行，关闭 version 或者 oid
		else if((iter - v.begin()) == 2) {
			if(isver == true) {
				if((iter - v.begin()) != 2) {
					cout << "Closure <version> not clean:"<< *iter << "." << endl;
					return(false);
				}
				if(token.front() != "}") {
					cout << "Closure <version> not clean:"<< *iter << "." << endl;
					return(false);
				}
				else {
					return(true);
				}
			}
			else {
				long long c;
				out.clear();
				out << token.front();
				out >> c;
				if(c < 0) {
					cout << "Number overflow :"<< *iter << "." << endl;
					return(false);
				}
				else {
					if(((entry.key >> 56) & 0xff) > 8) {
						entry.high.entry.oid = c;
					}
					else {
						entry.low.entry.oid = c;
					}
				}
			}
		}
		//其它行，对象属性
		else {
			if(token.front() == "}") {
				this->list.push_back(entry);
				return(true);
			}
			else if(token.size() < 3) {
				cout << "Too less element in this line :"<< *iter << "." << endl;
				return(false);
			}
			else {
				if(lexcion::rights(((iter - v.begin()) - 3), token, entry) != true) {
					cout << "Rights or significance analysing faild :"<< *iter << "." << endl;
					return(false);
				}
			}
		}
	}

	return(true);
}

/**
  * 结束语法分析器，生成文件
  *
  */
bool lexcion::finish() {
	struct __cosem_param param;
	
	if(this->version == 0) {
		cout << "No version field specified." << endl;
		return(false);
	}

	memset(reinterpret_cast<char *>(&param), 0, sizeof(param));

	sort(this->list.begin(),this->list.end(),lexcion::comp);

	if(this->list.size() >= (sizeof(param.entry) / sizeof(union __cosem_entry_file))) {
		cout << "Too many entries." << endl;
		return(false);
	}

	param.header.amount = this->list.size();

	for(uint16_t loop = 0; loop < 8; loop++) {
		param.header.spread[loop] = 0;
		for(vector<union __cosem_entry_file>::iterator iter = this->list.begin(); iter != this->list.end(); iter++) {
			if((iter->key) | (1<<loop)) {
				param.header.spread[loop] += 1;
			}
		}
	}

	param.header.check = lexcion::crc(&param.header, (sizeof(struct __cosem_param_header) - sizeof(uint32_t)));

	param.info.version = this->version;
	param.info.date = time(NULL);

	for(vector<union __cosem_entry_file>::iterator iter = this->list.begin(); iter != this->list.end(); iter++) {
		if(((iter->key >> 56) & 0xff) > 8) {
			iter->high.check = lexcion::crc(&iter->high.entry, sizeof(iter->high.entry));
		}
		else {
			iter->low.check = lexcion::crc(&iter->low.entry, sizeof(iter->low.entry));
		}

		param.entry[iter - this->list.begin()] = *iter;
	}

	//计算md5
	int ret = mbedtls_md5_ret(reinterpret_cast<const unsigned char *>(&param.entry[0]), \
								sizeof(param.entry[0])*this->list.size(), \
								reinterpret_cast<unsigned char *>(param.info.md5));
	if( ret != 0 ) {
		cout << "Calculate md5 faild." << endl;
		return(false);
	}

	param.info.check = lexcion::crc(&param.info, (sizeof(struct __cosem_param_info) - sizeof(uint32_t)));

	ofstream out("dlex.bin", ios::binary);

	if(!out.is_open()) {
		cout << "File can't create." << endl;
	}

	out.write(reinterpret_cast<char *>(&param), (sizeof(param) - sizeof(param.entry)));
	out.write(reinterpret_cast<char *>(&param.entry), (sizeof(param.entry[0]) * param.header.amount));
	out.close();
	
	cout << this->list.size() << " entries found." << endl;

	return(true);
}

/**
  * 程序入口
  *
  */
int main(int argc, char** argv) {

	if(argc != 2) {
		cout << "No file specified." << endl;
		getchar();
		return(0);
	}

	//打开文本文件
	ifstream in(argv[1]);
	if(!in.is_open()) {
		cout << "File can't open." << endl;
		getchar();
		return(0);
	}
	//按行读取文件
	string s = "";
	vector<string> file_line;
	while(getline(in,s)) {
		file_line.push_back(s);
	}
	in.close();

	//去除每行中的杂乱信息
	for(vector<string>::iterator iter = file_line.begin(); iter != file_line.end(); iter++) {
		//去除注释
		if(!iter->empty()) {
			if(iter->find("//") != iter->npos) {
				iter->erase(iter->find("//"));
			}
		}

		//替换tab为空格
		if(!iter->empty()) {
			replace(iter->begin(), iter->end(), '\t', ' ');
		}

		//去除行首空格
		if(!iter->empty()) {
			iter->erase(0,iter->find_first_not_of(" "));
		}
		//去除行尾空格
		if(!iter->empty()) {
			iter->erase(iter->find_last_not_of(" ") + 1);
		}
	}

	//去除空行
	vector<string> file_trim;
	for(vector<string>::iterator iter = file_line.begin(); iter != file_line.end(); iter++) {
		if(!iter->empty()) {
			file_trim.push_back(*iter);
		}
	}

	//解析生成二进制文件
	lexcion lex;
	if(lex.start() != true) {
		cout << "Lexcion start failed." << endl;
		getchar();
		return(0);
	}
	vector<string> closure;
	for(vector<string>::iterator iter = file_trim.begin(); iter != file_trim.end(); iter++) {
		if(iter->empty()) {
			cout << "Line is empty." << endl;
			getchar();
			return(0);
		}
		else if(iter->find("{") == 0) {
			closure.clear();
			closure.push_back(*iter);
		}
		else if(iter->find("{") != iter->npos) {
			cout << "\"{\" not at the first of line, string is :"<< *iter << "." << endl;
			getchar();
			return(0);
		}
		else if(iter->find("}") == 0) {
			closure.push_back(*iter);
			//closure 保存了两个花括号内的数据内容
			if(lex.append(closure) != true) {
				cout << "Append closure failed." << endl;
				getchar();
				return(0);
			}
		}
		else if(iter->find("}") != iter->npos) {
			cout << "\"}\" not at the first of line, string is :" << *iter << "." << endl;
			getchar();
			return(0);
		}
		else
		{
			closure.push_back(*iter);
		}
	}
	if(lex.finish() != true) {
		cout << "Generate failed." << endl;
		getchar();
		return(0);
	}

	//生成文件成功
	cout << "Generate succeed." << endl;

	//判断文件的大小端
	union {
		uint32_t a;
		uint8_t b;
	} u;
	u.a = 1;
	if (u.b == 0) {
		cout << "This file is in <big-endian>, ";
	}
	else if (u.b == 1) {
		cout << "This file is in <little-endian>, ";
	}
	cout << "please check if it's same to your target machine." << endl;

	getchar();
	return(0);
}