const FRAME_CTRL_POSITION_ENCRYPTED = 0;
const FRAME_CTRL_POSITION_CHECKSUM = 1;
const FRAME_CTRL_POSITION_DATA_DIRECTION = 2;
const FRAME_CTRL_POSITION_REQUIRE_ACK = 3;
const FRAME_CTRL_POSITION_FRAG = 4;
const DIRECTION_OUTPUT = 0;
const DIRECTION_INPUT = 1;
const AES_BASE_IV = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const NEG_SET_SEC_TOTAL_LEN = 0x00;
const NEG_SET_SEC_ALL_DATA = 0x01;
const PACKAGE_VALUE = 0x01;
const SUBTYPE_NEG = 0x00;
const SUBTYPE_WIFI_MODEl = 0x02;
const SUBTYPE_END = 0x03;
const PACKAGE_CONTROL_VALUE = 0x00;
const SUBTYPE_WIFI_NEG = 0x09;
const SUBTYPE_SET_SSID = 0x2;
const SUBTYPE_SET_PWD = 0x3;
const SUBTYPE_WIFI_LIST_NEG = 11;
const SUBTYPE_NEGOTIATION_NEG = 0;
const SUBTYPE_CUSTOM_DATA = 0x13;
var DH_P = "cf5cf5c38419a724957ff5dd323b9c45c3cdd261eb740f69aa94b8bb1a5c96409153bd76b24222d03274e4725a5406092e9e82e9135c643cae98132b0d95f7d65347c68afc1e677da90e51bbab5f5cf429c291b4ba39c6b2dc5e8c7231e46aa7728e87664532cdf547be20c9a3fa8342be6e34371a27c06f7dc0edddd2f86373";
var DH_G = "02";

const descSucListEN = ["Bluetooth connecting...", "Bluetooth connection successful", "Device information is successfully obtained", "Attribute information is successfully obtained", "Send configuration information...", "Configuration information sent successfully", "Connection successfully"];
const descFailListEN = ["Bluetooth connection failed", "Device information acquisition failed", "Attribute information acquisition failed", "Configuration information sent failed", "Distribution network failed"];

const descSucList = ["蓝牙连接...", "蓝牙连接成功", "设备信息已成功获取", "属性信息已成功获取", "发送配置信息...", "成功发送配置信息", "成功连接"];
const descFailList = ["蓝牙连接失败", "设备信息获取失败", "属性信息获取失败", "配置信息发送失败", "网络配置失败","蓝牙异常断开"];
const successList = {
  "0": "NULL",
  "1": "STA",
  "2": "SoftAP",
  "3": "SoftAP & STA"
};
const failList = {
  "0": "sequence error",
  "1": "checksum error",
  "2": "decrypt error",
  "3": "encrypt error",
  "4": "init security error",
  "5": "dh malloc error",
  "6": "dh param error",
  "7": "read param error",
  "8": "make public error"
};
var CRC_TB = [
  0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
  0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, 0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
  0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
  0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
  0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823, 0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
  0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
  0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
  0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70, 0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
  0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
  0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, 0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
  0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d, 0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
  0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
  0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
  0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a, 0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
  0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
  0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
];

// public static boolean isOldDevice(String blueToothName) {
//   if(org.apache.commons.lang3.StringUtils.isBlank(blueToothName)) {
//     return false;
//   }
//   //老设备编号
//   if(blueToothName.contains("S01")
//       || blueToothName.contains("S24")
//       || blueToothName.contains("TEST")) {
//     return true;
//   }
//   return false;
// }
function isOldDevice(blueToothName) {
  if(!blueToothName) {
    return true;
  }
  //老设备
  if(blueToothName.indexOf("S01") >= 0
      || blueToothName.indexOf("S24") >= 0
      || blueToothName.indexOf("TEST") >= 0) {
    return true;
  }
  if(blueToothName.indexOf("S02") >= 0) {
    return false;
  }
  return true;
}
//转16进制
const ab2hex = buffer => {
  var hexArr = Array.prototype.map.call(
    new Uint8Array(buffer),
    function(bit) {
      return ('00' + bit.toString(16)).slice(-2)
    }
  )
  return hexArr;
}

function string2buffer(str) {
  // 首先将字符串转为16进制
  let val = ""
  for (let i = 0; i < str.length; i++) {
    if (val === '') {
      val = str.charCodeAt(i).toString(16)
    } else {
      val += ',' + str.charCodeAt(i).toString(16)
    }
  }
  // 将16进制转化为ArrayBuffer
  return new Uint8Array(val.match(/[\da-f]{2}/gi).map(function (h) {
    return parseInt(h, 16)
  })).buffer
}
//16进制转字符串
const hexCharCodeToStr = hexCharCodeStr => {
  var trimedStr = hexCharCodeStr.trim();
  var rawStr =
    trimedStr.substr(0, 2).toLowerCase() === "0x" ? trimedStr.substr(2) : trimedStr;
  var len = rawStr.length;
  if (len % 2 !== 0) {
    alert("Illegal Format ASCII Code!");
    return "";
  }
  var curCharCode;
  var resultStr = [];
  for (var i = 0; i < len; i = i + 2) {
    curCharCode = parseInt(rawStr.substr(i, 2), 16); // ASCII Code Value
    resultStr.push(String.fromCharCode(curCharCode));
  }
  return resultStr.join("");
}
//过滤名称
const filterDevice = (devices, filterName) => {
  var self = this,
    list = [];
  for (var i = 0; i < devices.length; i++) {
    var device = devices[i];
    var re = new RegExp("^(" + filterName + ")");
    if (re.test(device["name"])) {
      list.push(device);
    }
  }
  return list;
}
//获去type
const getType = (pkgType, subType) => {
  return (subType << 2) | pkgType;
}
//unit8Arry转数组
const uint8ArrayToArray = uint8Array => {
  var array = [];

  for (var i = 0; i < uint8Array.byteLength; i++) {
    array[i] = uint8Array[i];
  }

  return array;
}
//16进制转二进制数组
const hexToBinArray = str => {
  var dec = parseInt(str, 16),
    bin = dec.toString(2),
    len = bin.length;
  if (len < 8) {
    var diff = 8 - len,
      zeros = "";
    for (var i = 0; i < diff; i++) {
      zeros += "0";
    }
    bin = zeros + bin;
  }
  return bin.split("");
}
//16进制转数组
const hexByArray = str => {
  var arr = [];
  if (str.length % 2 != 0) {
    str = "0" + str;
  }
  for (var i = 0; i < str.length; i += 2) {
    arr.push(str.substring(i, i + 2))
  }
  return arr;
}
//16进制转整形数组
const hexByInt = str => {
  var arr = [];
  if (str.length % 2 != 0) {
    str = "0" + str;
  }
  for (var i = 0; i < str.length; i += 2) {
    arr.push(parseInt(str.substring(i, i + 2), 16))
  }
  return arr;
}
//排序
const sortBy = (attr, rev) => {
  //第二个参数没有传递 默认升序排列
  if (rev == undefined) {
    rev = 1;
  } else {
    rev = (rev) ? 1 : -1;
  }
  return function(a, b) {
    a = a[attr];
    b = b[attr];
    if (a < b) {
      return rev * -1;
    } else if (a > b) {
      return rev * 1;
    }
    return 0;
  }
}
//判断非空
const _isEmpty = str => {
  if (str === "" || str === null || str === undefined || str === "null" || str === "undefined") {
    return true;
  } else {
    return false;
  }
}
//组装数据格式
const writeData = (type, subType, frameCtl, seq, len, data) => {
  var value = [],type = getType(type, subType);
  value.push(type);
  value.push(frameCtl);
  value.push(seq);
  value.push(len);
  if (!_isEmpty(data)) {
    value = value.concat(data);
  }
  return value;
}
//是否分包
const isSubcontractor = (data, checksum, sequence, encrypt) => {
  var len = 0,
    lenData = [],
    laveData = [],
    flag = false;
  var total = data.length;
  if (total > 16) {
    if (checksum) {
      lenData = data.slice(0, 12);
      laveData = data.slice(12);
    } else {
      lenData = data.slice(0, 14);
      laveData = data.slice(14);
    }
    var len1 = (total >> 8) & 0xff;
    var len2 = total & 0xff;
    lenData.splice(0, 0, len1);
    lenData.splice(0, 0, len2);
    len = lenData.length;
    flag = true;
  } else {
    lenData = data;
    len = lenData.length;
  }
  if (checksum) {
    lenData = assemblyChecksum(lenData, len, sequence);
  }
  return {
    "len": len,
    "lenData": lenData,
    "laveData": laveData,
    "flag": flag
  }
}
const assemblyChecksum = (list, len, sequence, encrypt) => {
  var checkData = [];
  checkData.push(sequence);
  checkData.push(len);
  checkData = checkData.concat(list);
  var crc = caluCRC(0, checkData);
  var checksumByte1 = crc & 0xff;
  var checksumByte2 = (crc >> 8) & 0xff;
  list.push(checksumByte1);
  list.push(checksumByte2);
  return list;
}
//加密发送的数据
const encrypt = (aesjs, md5Key, sequence, data, checksum) => {
  var iv = generateAESIV(sequence),
    sumArr = [],
    list = [];
  if (checksum) {
    var len = data.length - 2;
    list = data.slice(0, len);
    sumArr = data.slice(len);
  } else {
    list = data;
  }
  var encryptData = uint8ArrayToArray(blueAesEncrypt(aesjs, md5Key, iv, new Uint8Array(list)));
  return encryptData.concat(sumArr);
}

//DH加密
const blueDH = (p, g, crypto) => {
  var client = crypto.createDiffieHellman(p, "hex", g, "hex");
  var clientKey = client.generateKeys();
  //var clientSecret = client.computeSecret(server.getPublicKey());
  return client;
}
//md5加密
const blueMd5 = (md5, key) => {
  var arr = md5.array(key);
  return arr;
}
// aes加密
const blueAesEncrypt = (aesjs, mdKey, iv, bytes) => {
  var aesOfb = new aesjs.ModeOfOperation.ofb(mdKey, iv);
  var encryptedBytes = aesOfb.encrypt(bytes);
  return encryptedBytes;
}
//aes解密
const blueAesDecrypt = (aesjs, mdKey, iv, bytes) => {
  var aesOfb = new aesjs.ModeOfOperation.ofb(mdKey, iv);
  var decryptedBytes = aesOfb.decrypt(bytes);
  return decryptedBytes;
}
//获取Frame Control
const getFrameCTRLValue = (encrypted, checksum, direction, requireAck, frag) => {
  var frame = 0;
  if (encrypted) {
    frame = frame | (1 << FRAME_CTRL_POSITION_ENCRYPTED);
  }
  if (checksum) {
    frame = frame | (1 << FRAME_CTRL_POSITION_CHECKSUM);
  }
  if (direction == DIRECTION_INPUT) {
    frame = frame | (1 << FRAME_CTRL_POSITION_DATA_DIRECTION);
  }
  if (requireAck) {
    frame = frame | (1 << FRAME_CTRL_POSITION_REQUIRE_ACK);
  }
  if (frag) {
    frame = frame | (1 << FRAME_CTRL_POSITION_FRAG);
  }
  return frame;
}
//获取aes iv
const generateAESIV = sequence => {
  var result = [];
  for (var i = 0; i < 16; i++) {
    if (i == 0) {
      result[0] = sequence;
    } else {
      result[i] = AES_BASE_IV[i];
    }
  }
  return result;
}
//计算CRC值
const caluCRC = (crc, pByte) => {
  crc = (~crc) & 0xffff;
  for (var i in pByte) {
    crc = CRC_TB[((crc & 0xffff) >> 8) ^ (pByte[i] & 0xff)] ^ ((crc & 0xffff) << 8);
  }
  return (~crc) & 0xffff;
}

function showToast(title,icon){
  wx.showToast({
    title: title,
    duration: 2000,
	icon:icon
  })
}

function showLoading(title){
  wx.showLoading({
    title: title,
  })
}

function getHttpRequest(res) {
  if(res.code !== 200) {
    uni.showToast({
      title: res.message,
      icon: 'none'
    })
    //请求异常
    return false;
  }
  //请求正常
  return true;
}

function getMaxOrMin(min, max, spacing) {
  if(min < 0) {
    min = 0;
  }
  //跨度为5的处理
  if(spacing === 5) {
    if(max - min === 35) {
      max = max + 5;
    }
    if(max - min === 45) {
      max = max + 5;
    }
  }
  //跨度为10的处理
  if(spacing === 10) {
    if(max - min === 70) {
      max = max + 10;
    }

  }

  return [min, max]
}

/**
 * 呼吸率曲线图坐标自适应 - 线条
 * @param value
 * @returns {number}
 */
function bretheOptsSplitNumber(value) {
  let splitNumber = 3;
  if(value === 10) {
    //0 5 10
    splitNumber = 2
  }
  else if(value === 15) {
    //0 5 10 15
    splitNumber = 3
  }
  else if(value === 20) {
    //0 5 10 15 20
    splitNumber = 4
  }
  else if(value === 25) {
    //0 5 10 15 20 25
    splitNumber = 5
  }
  else if(value === 30) {
    //0 10 20 30
    splitNumber = 3
  }
  else if(value === 35) {
    //0 7 14 21 28 35 todo 无法整数 暂时处理是35+5变为40
    splitNumber = 5
  }
  else if(value === 40) {
    //0 10 20 30 40
    splitNumber = 4
  }
  else if(value === 45) {
    //0 9 18 27 36 45 todo 无法整数 暂时处理是45+5变为50
    splitNumber = 5
  }
  else if(value === 50) {
    //0 10 20 30 40 50
    splitNumber = 5
  }
  return splitNumber;
}

/**
 * 心率曲线图坐标自适应 - 线条
 * @param value
 * @returns {number}
 */
function heartOptsSplitNumber(value) {
  let splitNumber = 3;
  if(value === 10) {
    //0 10
    splitNumber = 1
  }
  else if(value === 20) {
    //0 10 20
    splitNumber = 2
  }
  else if(value === 30) {
    //0 10 20 30
    splitNumber = 3
  }
  else if(value === 40) {
    //0 10 20 30 40
    splitNumber = 4
  }
  else if(value === 50) {
    //0 10 20 30 40 50
    splitNumber = 5
  }
  else if(value === 60) {
    //0 20 40 60
    splitNumber = 3
  }
  else if(value === 70) {
    //0 14 28 42 56 70  todo 无法整数 暂时处理为70+10变为80
    splitNumber = 5
  }
  else if(value === 80) {
    //0 20 40 60 80
    splitNumber = 4
  }
  else if(value === 90) {
    //0 30 60 90
    splitNumber = 3
  }
  else if(value === 100) {
    //0 20 40 60 80 100
    splitNumber = 5
  }
  else if(value === 120) {
    //0 30 60 90 120
    splitNumber = 4
  }
  return splitNumber;
}

function calcBretheMinMax(min, max) {
  if(max < 20) {
    return {
      min: 0,
      max: 20
    };
  }
  // let value = max - min;
  // if(value <= 10) {
  //   value = 10;
  // }
  // else if (value > 10 && value <= 20) {
  //   value = 20;
  // }
  // else if (value > 20 && value <= 50) {
  //   value = 50;
  // }
  // if(value == 10) {
  //   return [0, 10]
  // }
  // else if(value == 20) {
  //   return [0, 20]
  // }
  // else if (value == 50) {
  //   return [0, 50]
  // }
  // return [min, max]
  if (min > 5) {
    min = min % 5 > 0 ? (min - min % 5) : min - 5;
  }
  const sub = max - min;
  max = max + (4 - sub / 5 % 4) * 5;
  return {
    min,
    max
  };
}

function getDayStr(date) {
  date = new Date(date);
  let year = date.getFullYear();
  let month = date.getMonth() + 1;
  let day = date.getDate()
  if(month < 10) {
    month = '0' + month;
  }
  if(day < 10) {
    day = '0' + day
  }
  return year + '-' + month + '-' + day;
}

function formatDate(date) {
  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  return `${year}-${month}-${day}`; // 格式化为YYYY-MM-DD
}

/**
 * 预警时间验证
 */
function warningTimeVerificationStartTimeV1(startTime, endTime) {
  var beginHour = startTime.split(":")[0]
  var beginMinutes = startTime.split(":")[1]
  var endHour = endTime.split(":")[0]
  var endHourMinutes = endTime.split(":")[1]
  //结束时间是当日
  if(endHour >= 19 && endHour <= 24) {
    //开始时间要小于结束时间
    if(beginHour < endHour) {
      return true
    }
  }
  //结束时间是次日
  if(endHour >= 0 && endHour <= 11) {
    //如果开始时间是当日
    if(beginHour >= 19 && beginHour <= 24) {
      //开始时间要大于结束时间
      if(beginHour > endHour) {
        return true
      }
    }
    //如果开始时间是次日
    if(beginHour >= 0 && beginHour <= 11) {
      //开始时间要小于结束时间
      if(beginHour < endHour) {
        return true
      }
    }
  }

  //小时相同 开始时间分钟要小于结束时间分钟
  if(beginHour == endHour) {
    if(beginMinutes < endHourMinutes) {
      return true;
    }
  }
  if(startTime === endTime) {
    // uni.showToast({
    //   title: "请选择开始时间",
    //   icon: 'none',
    // })
    return false;
  }
  uni.showToast({
    title: "开始时间不得大于或等于结束时间",
    icon: 'none',
  })
  return false;
}

/**
 * 预警时间验证
 */
function warningTimeVerificationEndTimeV1(startTime, endTime) {
  var beginHour = startTime.split(":")[0]
  var beginMinutes = startTime.split(":")[1]
  var endHour = endTime.split(":")[0]
  var endHourMinutes = endTime.split(":")[1]
  //开始时间是当日
  if(beginHour >= 19 && beginHour <= 24) {
    //如果结束时间是当日
    if(endHour >= 19 && endHour <= 24) {
      //结束时间要大于或等于开始时间
      if(endHour > beginHour) {
        return true
      }
    }
    //如果结束时间是次日
    if(endHour >= 0 && endHour <= 11) {
      //结束时间要大于或等于开始时间
      if(endHour < beginHour) {
        return true
      }
    }
  }
  //开始时间是次日
  if(beginHour >= 0 && beginHour <= 11) {
    //如果结束时间是当日
    if(endHour >= 19 && endHour <= 24) {
      uni.showToast({
        title: "结束时间不得小于或等于开始时间",
        icon: 'none',
      })
      return false;
    }
    //开始时间要小于或等于结束时间
    if(endHour > beginHour) {
      return true
    }
  }

  if(beginHour == endHour) {
    if(beginMinutes < endHourMinutes) {
      return true
    }
  }
  if(startTime === endTime) {
    // uni.showToast({
    //   title: "请选择结束时间",
    //   icon: 'none',
    // })
    return false;
  }
  uni.showToast({
    title: "结束时间不得小于或等于开始时间",
    icon: 'none',
  })
  return false;
}

module.exports = {
  _isEmpty: _isEmpty,
  ab2hex: ab2hex,
  hexCharCodeToStr: hexCharCodeToStr,
  filterDevice: filterDevice,
  getType: getType,
  hexToBinArray: hexToBinArray,
  hexByArray: hexByArray,
  hexByInt: hexByInt,
  sortBy: sortBy,
  writeData: writeData,
  isSubcontractor: isSubcontractor,
  getFrameCTRLValue: getFrameCTRLValue,
  blueDH: blueDH,
  blueMd5: blueMd5,
  blueAesEncrypt: blueAesEncrypt,
  blueAesDecrypt: blueAesDecrypt,
  uint8ArrayToArray: uint8ArrayToArray,
  generateAESIV: generateAESIV,
  caluCRC: caluCRC,
  encrypt: encrypt,
  DH_P: DH_P,
  DH_G: DH_G,
  DIRECTION_OUTPUT: DIRECTION_OUTPUT,
  DIRECTION_INPUT: DIRECTION_INPUT,
  NEG_SET_SEC_TOTAL_LEN: NEG_SET_SEC_TOTAL_LEN,
  NEG_SET_SEC_ALL_DATA: NEG_SET_SEC_ALL_DATA,
  PACKAGE_VALUE: PACKAGE_VALUE,
  SUBTYPE_NEG: SUBTYPE_NEG,
  PACKAGE_CONTROL_VALUE: PACKAGE_CONTROL_VALUE,
  SUBTYPE_WIFI_NEG: SUBTYPE_WIFI_NEG,
  SUBTYPE_WIFI_LIST_NEG: SUBTYPE_WIFI_LIST_NEG,
  SUBTYPE_NEGOTIATION_NEG: SUBTYPE_NEGOTIATION_NEG,
  SUBTYPE_WIFI_MODEl: SUBTYPE_WIFI_MODEl,
  SUBTYPE_SET_SSID: SUBTYPE_SET_SSID,
  SUBTYPE_SET_PWD: SUBTYPE_SET_PWD,
  SUBTYPE_END: SUBTYPE_END,
  SUBTYPE_CUSTOM_DATA: SUBTYPE_CUSTOM_DATA,
  descSucList: descSucList,
  descFailList: descFailList,
  successList: successList,
  failList: failList,

  showToast: showToast,
  showLoading: showLoading,

  bretheOptsSplitNumber: bretheOptsSplitNumber,
  heartOptsSplitNumber: heartOptsSplitNumber,
  getHttpRequest: getHttpRequest,
  getMaxOrMin: getMaxOrMin,
  calcBretheMinMax: calcBretheMinMax,
  getDayStr:getDayStr,
  formatDate: formatDate,
  string2buffer: string2buffer,
  warningTimeVerificationStartTimeV1:warningTimeVerificationStartTimeV1,
  warningTimeVerificationEndTimeV1:warningTimeVerificationEndTimeV1,

  isOldDevice:isOldDevice,

}
