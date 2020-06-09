/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __DLEX_H__
#define __DLEX_H__

/* Includes ------------------------------------------------------------------*/
#include "stdint.h"

/* Exported types ------------------------------------------------------------*/
#pragma pack(push)
#pragma pack(4)

/**
  * @brief  类型
  */
enum __meta_item
{
    M_NULL = 0,//未定义
    M_P_ENERGY = 1,//有功电能（mWh）
    M_Q_ENERGY = 2,//无功电能（mVarh）
    M_S_ENERGY = 3,//视在电能（mVAh）
    M_P_POWER = 4,//有功功率（mW）
    M_Q_POWER = 5,//无功功率（mVar）
    M_S_POWER = 6,//视在功率（mVA）
    M_VOLTAGE = 7,//电压（mV）
    M_CURRENT = 8,//电流（mA）
    M_POWER_FACTOR = 9,//功率因数（1/1000）
    M_ANGLE = 10,//相角（1/1000度）
    M_FREQUENCY = 11,//频率（1/1000Hz）
    /** 以上数据的格式是已知的，不需要指定 */
    
/**
  * @brief  当显示列表中添加非计量数据时，显示任务不清楚获取到的数据
  *         需要以怎样的格式来显示，默认显示为十进制，当需要显示为非
  *         十进制格式，则需要在这里显式地指定
  */
    FMT_BIN = 24,//二进制格式
    FMT_HEX = 25,//十六进制格式
    FMT_DATE = 26,//日期格式
    FMT_TIME = 27,//时间格式
    FMT_DTIME = 28,//一年内时间格式
    FMT_BCD = 29,//BCD格式
    FMT_ASCII = 30,//ASCII字符流格式
    FMT_STR = 31,//二进制字符流格式
};

/**
  * @brief  分相标识
  */
enum __meta_phase
{
    M_PHASE_N = 0,//N相
	M_PHASE_A = 1,//A相
	M_PHASE_B = 2,//B相
	M_PHASE_C = 4,//C相
	M_PHASE_AB = 3,//AB
	M_PHASE_AC = 5,//AC
	M_PHASE_BC = 6,//BC
    M_PHASE_T = 7,//总
};

/**
  * @brief  缩放
  */
enum __meta_scale
{
    M_SCALE_N8 = 23,    //x 100000000 -> x100000
	M_SCALE_N7 = 25,    //x 10000000 -> x10000
	M_SCALE_N6 = 25,    //x 1000000 -> x1000
	M_SCALE_N5 = 26,    //x 100000 -> x100
    M_SCALE_N4 = 27,    //x 10000 -> x10
	M_SCALE_N3 = 28,    //x 1000 -> x1
	M_SCALE_N2 = 29,    //x 100 -> x1/10
	M_SCALE_N1 = 30,    //x 10 -> x1/100
    M_SCALE_ZN = 31,    //x 1 -> x1000
    M_SCALE_ZP = 0,     //x 1 -> x1/1000
    M_SCALE_P1 = 1,     //x 1/10 -> x1/10000
    M_SCALE_P2 = 2,     //x 1/100 -> x1/100000
    M_SCALE_P3 = 3,     //x 1/1000 -> x1/1000000
    M_SCALE_P4 = 4,     //x 1/10000 -> x1/10000000
    M_SCALE_P5 = 5,     //x 1/100000 -> x1/100000000
    M_SCALE_P6 = 6,     //x 1/1000000 -> x1/1000000000
    M_SCALE_P7 = 7,     //x 1/10000000 -> x1/10000000000
    M_SCALE_P8 = 8,     //x 1/100000000 -> x1/100000000000
};

/**
  * @brief  象限标识
  */
enum __meta_quad
{
    M_QUAD_N = 0x00,//无
	M_QUAD_I = 0x01,//1象限
	M_QUAD_II = 0x02,//2象限
	M_QUAD_III = 0x04,//3象限
    M_QUAD_IV = 0x08,//4象限
    
	M_QUAD_NI = 0x10,//减1象限
	M_QUAD_NII = 0x20,//减2象限
	M_QUAD_NIII = 0x40,//减3象限
    M_QUAD_NIV = 0x80,//减4象限
	
	M_QUAD_DEMAND = 0x100,//标识该数据是需量而不是功率
};

/**
  * @brief  历史记录
  */
enum __meta_history
{
	M_HIST = 0x200,//历史记录标记（上0次）
	M_HIST_01 = 0x210,//上1次
	M_HIST_02 = 0x220,//上2次
	M_HIST_03 = 0x230,//上3次
	M_HIST_04 = 0x240,//上4次
	M_HIST_05 = 0x250,//上5次
	M_HIST_06 = 0x260,//上6次
	M_HIST_07 = 0x270,//上7次
	M_HIST_08 = 0x280,//上8次
	M_HIST_09 = 0x290,//上9次
	M_HIST_10 = 0x2a0,//上10次
	M_HIST_11 = 0x2b0,//上11次
	M_HIST_12 = 0x2c0,//上12次
	M_HIST_13 = 0x2d0,//上13次
	M_HIST_14 = 0x2e0,//上14次
	M_HIST_15 = 0x2f0,//上15次
};



/**
  * @brief   AXDR 数据类型
  */
enum __axdr_type
{
    AXDR_NULL = 0,              // 0 
    AXDR_ARRAY,                 // 1 
    AXDR_STRUCTURE,             // 2 
    AXDR_BOOLEAN,               // 3 boolean
    AXDR_BIT_STRING,            // 4 An ordered sequence of boolean values
    AXDR_DOUBLE_LONG,           // 5 Integer32
    AXDR_DOUBLE_LONG_UNSIGNED,  // 6 Unsigned32
    
    AXDR_OCTET_STRING = 9,      // 9 An ordered sequence of octets (8 bit bytes)
    AXDR_VISIBLE_STRING,        // 10 An ordered sequence of ASCII characters
    
    AXDR_UTF8_STRING = 12,      // 11 An ordered sequence of characters encoded as UTF-8
    AXDR_BCD,                   // 12 binary coded decimal
    
    AXDR_INTEGER = 15,          // 15 Integer8
    AXDR_LONG,                  // 16 Integer16
    AXDR_UNSIGNED,              // 17 Unsigned8
    AXDR_LONG_UNSIGNED,         // 18 Unsigned16
    AXDR_COMPACT_ARRAY,         // 19 
    
    AXDR_LONG64 = 20,           // 20 Integer64
    AXDR_LONG64_UNSIGNED,       // 21 Unsigned64
    AXDR_ENUM,                  // 22 enum
    AXDR_FLOAT32,               // 23 OCTET STRING (SIZE(4))
    AXDR_FLOAT64,               // 24 OCTET STRING (SIZE(8))
    AXDR_DATE_TIME,             // 25 OCTET STRING SIZE(12))
    AXDR_DATE,                  // 26 OCTET STRING (SIZE(5))
    AXDR_TIME,                  // 27 OCTET STRING (SIZE(4))
};

/**
  * DLMS的 Class
  *
  */
enum __dlms_class
{
    CLASS_DATA = 1,
    CLASS_REGISTER = 3,
    CLASS_EXTREGISTER = 4,
    CLASS_DEMANDREGISTER = 5,
    CLASS_PROFILE = 7,
    CLASS_CLOCK = 8,
    CLASS_SCRIPT = 9,
    CLASS_SCHEDULE = 10,
    CLASS_SPECIALDAY = 11,
    CLASS_ASSOCIATION_LN = 15,
    CLASS_SAP = 17,
    CLASS_IMAGE_TRANSFER = 18,
    CLASS_ACTIVITYCALENDER = 20,
    CLASS_REGISTER_MONITOR = 21,
    CLASS_SINGLE_ACTION = 22,
    CLASS_HDLC_SETUP = 23,
    CLASS_MAC_ADDRESS_SETUP = 43,
    CLASS_RELAY = 70,
    CLASS_LIMITER = 71,
};

/**
  * DLMS 属性的访问权限
  *
  */
enum __dlms_attr_right
{
    ATTR_NONE = 0,
    ATTR_READ = 0x01,
    ATTR_WRITE = 0x02,
    ATTR_AUTHREQ = 0x04,
    ATTR_ENCREQ = 0x08,
    ATTR_DIGITREQ = 0x10,
    ATTR_AUTHRSP = 0x20,
    ATTR_ENCRSP = 0x40,
    ATTR_DIGITRSP = 0x80,
};

/**
  * DLMS 方法的访问权限
  *
  */
enum __dlms_method_right
{
    METHOD_NONE = 0,
    METHOD_ACCESS = 0x01,
    METHOD_AUTHREQ = 0x04,
    METHOD_ENCREQ = 0x08,
    METHOD_DIGITREQ = 0x10,
    METHOD_AUTHRSP = 0x20,
    METHOD_ENCRSP = 0x40,
    METHOD_DIGITRSP = 0x80,
};


/**
  * @brief  cosem 数据项简版
  * 用于描述 类 1 3 4 5 6 7 8
  * 这些类的实例中最多有三个属性可以被MID描述其物理意义
  * 具体可描述哪些属性，参考下表：
  * Data                attr 2
  * Register            attr 2 3
  * Extended register   attr 2 3 5
  * Demand register     attr 2 3 4
  * Register activation attr 
  * Profile generic     attr 4 7 8
  * Clock               attr 2 3
  */
struct __cosem_entry_low
{
    uint64_t key;//8 {classID groupA groupB groupC groupD groupE groupF suit}
    uint32_t oid;//4
    uint32_t mid[3];//3*4
    uint8_t right[16][3];//3*16
};

/**
  * @brief  cosem 数据项简版
  * struct __cosem_entry_low 的存储版，带校验，用于从文件中加载
  */
struct __cosem_entry_low_file
{
    struct __cosem_entry_low entry;
    uint32_t check;//crc32校验
};

/**
  * @brief  cosem 数据项
  * 用于描述 类号大于 8 的类
  */
struct __cosem_entry_high
{
    uint64_t key;//8 {classID groupA groupB groupC groupD groupE groupF suit}
    uint32_t oid;//4
    uint8_t right[24][3];//3*24
};

/**
  * @brief  cosem 数据项
  * struct __cosem_entry_high 的存储版，带校验，用于从文件中加载
  */
struct __cosem_entry_high_file
{
    struct __cosem_entry_high entry;
    uint32_t check;//crc32校验
};

/**
  * @brief  cosem 数据项
  * struct 用于从文件中加载
  */
union __cosem_entry_file
{
    uint64_t key;
    struct __cosem_entry_low_file low;
    struct __cosem_entry_high_file high;
    uint8_t size[96];
};

/**
  * @brief  cosem 数据项文件头
  */
struct __cosem_param_header
{
    uint16_t amount; //数据项条数
	uint16_t spread[8]; //分类后数据项条数（suit 1~8）
	uint16_t reserve;
    uint32_t check; //crc32校验
};

/**
  * @brief  cosem 数据项文件信息
  */
struct __cosem_param_info
{
    uint64_t version; //数据发布版本
    uint64_t date; //数据发布时间（时间戳）
    uint8_t md5[16];//amount 个 entry 的md5校验
    uint32_t check; //crc32校验
};

/**
  * @brief  cosem 数据项存储空间分布
  */
struct __cosem_param
{
    struct __cosem_param_header header;
    struct __cosem_param_info info;
	uint8_t reserve[sizeof(union __cosem_entry_file) - sizeof(struct __cosem_param_header) - sizeof(struct __cosem_param_info)];
    union __cosem_entry_file entry[(64*1024)/sizeof(union __cosem_entry_file) - 1];
};

/* Exported constants --------------------------------------------------------*/
/* Exported macro ------------------------------------------------------------*/
/* Exported function prototypes ----------------------------------------------*/

#pragma pack(pop)

#endif /* __DLEX_H__ */
