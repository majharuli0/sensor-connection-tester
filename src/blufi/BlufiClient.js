import { BleManager } from 'react-native-ble-plx';
import { Buffer } from 'buffer';
import { EventEmitter } from 'events';
import * as util from './util';
import * as crypto from './crypto/crypto-dh';
import md5 from './crypto/md5.min';
import aesjs from './crypto/aes';

const manager = new BleManager();
const eventEmitter = new EventEmitter();

const SERVICE_UUID = "0000FFFF-0000-1000-8000-00805F9B34FB";
const CHAR_WRITE_UUID = "0000FF01-0000-1000-8000-00805F9B34FB";
const CHAR_READ_UUID = "0000FF02-0000-1000-8000-00805F9B34FB";

let sequenceControl = 0;
let mClient = null;
let mMD5Key = 0;
let mIsEncrypt = true;
let mIsChecksum = true;
let mConnectedDevice = null;

// Helper to convert Buffer to Hex String
function buf2hex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// Helper to convert Hex String to Buffer
function hex2buf(hex) {
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
}

class BlufiClient {
    constructor() {
        this.manager = manager;
    }

    on(event, listener) {
        eventEmitter.on(event, listener);
    }

    off(event, listener) {
        eventEmitter.removeListener(event, listener);
    }

    async scan() {
        return new Promise((resolve, reject) => {
            const devices = [];
            this.manager.startDeviceScan(null, null, (error, device) => {
                if (error) {
                    reject(error);
                    return;
                }
                if (device.name && device.name.startsWith("BLUFI")) {
                    if (!devices.find(d => d.id === device.id)) {
                        devices.push(device);
                        eventEmitter.emit('deviceFound', device);
                    }
                }
            });

            // Stop scan after 5 seconds
            setTimeout(() => {
                this.manager.stopDeviceScan();
                resolve(devices);
            }, 5000);
        });
    }

    async connect(deviceId) {
        try {
            const device = await this.manager.connectToDevice(deviceId);
            mConnectedDevice = device;
            await device.discoverAllServicesAndCharacteristics();

            // Enable notifications
            device.monitorCharacteristicForService(SERVICE_UUID, CHAR_READ_UUID, (error, characteristic) => {
                if (error) {
                    console.error("Notification error:", error);
                    return;
                }
                this.onCharacteristicChanged(characteristic.value);
            });

            return device;
        } catch (error) {
            console.error("Connection failed", error);
            throw error;
        }
    }

    async negotiateSecurity() {
        sequenceControl = 0;
        mClient = util.blueDH(util.DH_P, util.DH_G, crypto);
        const kBytes = util.uint8ArrayToArray(mClient.getPublicKey());
        const pBytes = util.hexByInt(util.DH_P);
        const gBytes = util.hexByInt(util.DH_G);

        const pgkLength = pBytes.length + gBytes.length + kBytes.length + 6;
        const pgkLen1 = (pgkLength >> 8) & 0xff;
        const pgkLen2 = pgkLength & 0xff;

        const data = [];
        data.push(util.NEG_SET_SEC_TOTAL_LEN);
        data.push(pgkLen1);
        data.push(pgkLen2);

        const frameControl = util.getFrameCTRLValue(false, false, util.DIRECTION_OUTPUT, false, false);
        const value = util.writeData(util.PACKAGE_VALUE, util.SUBTYPE_NEG, frameControl, sequenceControl, data.length, data);

        await this.write(new Uint8Array(value));

        // Continue negotiation in getSecret (called recursively via onCharacteristicChanged logic if needed, 
        // but here we just start the process)
        this.getSecret(kBytes, pBytes, gBytes, null);
    }

    async getSecret(kBytes, pBytes, gBytes, data) {
        let obj = [];
        let frameControl = 0;
        sequenceControl = parseInt(sequenceControl) + 1;

        if (!util._isEmpty(data)) {
            obj = util.isSubcontractor(data, true, sequenceControl);
            frameControl = util.getFrameCTRLValue(false, true, util.DIRECTION_OUTPUT, false, obj.flag);
        } else {
            data = [];
            data.push(util.NEG_SET_SEC_ALL_DATA);
            const pLength = pBytes.length;
            data.push((pLength >> 8) & 0xff);
            data.push(pLength & 0xff);
            data = data.concat(pBytes);

            const gLength = gBytes.length;
            data.push((gLength >> 8) & 0xff);
            data.push(gLength & 0xff);
            data = data.concat(gBytes);

            const kLength = kBytes.length;
            data.push((kLength >> 8) & 0xff);
            data.push(kLength & 0xff);
            data = data.concat(kBytes);

            obj = util.isSubcontractor(data, true, sequenceControl);
            frameControl = util.getFrameCTRLValue(false, true, util.DIRECTION_OUTPUT, false, obj.flag);
        }

        const value = util.writeData(util.PACKAGE_VALUE, util.SUBTYPE_NEG, frameControl, sequenceControl, obj.len, obj.lenData);
        await this.write(new Uint8Array(value));

        if (obj.flag) {
            await this.getSecret(kBytes, pBytes, gBytes, obj.laveData);
        }
    }

    async postCustomData(dataString) {
        // Convert string to byte array
        const dataBytes = [];
        for (let i = 0; i < dataString.length; i++) {
            dataBytes.push(dataString.charCodeAt(i));
        }
        await this.writeCustomDataRecursive(dataBytes);
    }

    async writeCustomDataRecursive(data) {
        let obj = {};
        let frameControl = 0;
        sequenceControl = parseInt(sequenceControl) + 1;

        if (!util._isEmpty(data)) {
            obj = util.isSubcontractor(data, mIsChecksum, sequenceControl, mIsEncrypt);
            frameControl = util.getFrameCTRLValue(mIsEncrypt, mIsChecksum, util.DIRECTION_OUTPUT, false, obj.flag);
        } else {
            // Should not happen for custom data entry
            return;
        }

        const defaultData = util.encrypt(aesjs, mMD5Key, sequenceControl, obj.lenData, true);
        const value = util.writeData(util.PACKAGE_VALUE, util.SUBTYPE_CUSTOM_DATA, frameControl, sequenceControl, obj.len, defaultData);

        await this.write(new Uint8Array(value));

        if (obj.flag) {
            await this.writeCustomDataRecursive(obj.laveData);
        }
    }

    async write(uint8Array) {
        if (!mConnectedDevice) return;
        const base64Data = Buffer.from(uint8Array).toString('base64');
        await mConnectedDevice.writeCharacteristicWithResponseForService(
            SERVICE_UUID,
            CHAR_WRITE_UUID,
            base64Data
        );
    }

    onCharacteristicChanged(base64Value) {
        const buffer = Buffer.from(base64Value, 'base64');
        const list2 = Array.from(buffer); // Convert to array of numbers
        const hexList = list2.map(x => ('00' + x.toString(16)).slice(-2)); // For debugging/logic

        if (list2.length < 4) return;

        const val = list2[0];
        const type = val & 3;
        const subType = val >> 2;

        // Decrypt if needed (simplified logic from blufi.js)
        // Note: Real implementation needs to handle fragmentation (result accumulation)
        // For this demo, we assume single packet or handle simple cases

        // ... (Logic to handle negotiation response and set mMD5Key)
        if (type === 1 && subType === util.SUBTYPE_NEGOTIATION_NEG) {
            // This is where we handle the DH response
            // We need to strip headers and decrypt if encrypted (usually neg response is not encrypted but checked)
            // Simplified:
            const len = list2.length;
            const data = list2.slice(4, len - 2); // Strip header and checksum (approx)

            const clientSecret = mClient.computeSecret(new Uint8Array(data));
            mMD5Key = md5.array(clientSecret);
            console.log("Security Negotiated. MD5 Key set.");
            eventEmitter.emit('securitySuccess');
        }

        if (type === 1 && subType === 19) { // Custom Data
            // Decrypt
            // ...
            // Emit custom data
            eventEmitter.emit('customData', list2);
        }
    }
}

export default new BlufiClient();
