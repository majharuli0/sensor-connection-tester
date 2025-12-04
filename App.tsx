import React, { useState, useEffect } from 'react';
import { View, Text, Button, TextInput, Alert, StyleSheet, ScrollView, TouchableOpacity, PermissionsAndroid, Platform } from 'react-native';
import BlufiClient from './src/blufi/BlufiClient';

export default function App() {
  const [logs, setLogs] = useState<string[]>([]);
  const [mqttIp, setMqttIp] = useState('3.104.3.162');
  const [status, setStatus] = useState('Disconnected');
  const [devices, setDevices] = useState<any[]>([]);

  const addLog = (msg: string) => setLogs(p => [`> ${msg}`, ...p]);

  useEffect(() => {
    requestPermissions();

    BlufiClient.on('securitySuccess', () => {
      addLog("Security Negotiation Successful!");
      setStatus("Secured");
    });

    BlufiClient.on('deviceFound', (device) => {
      setDevices(prev => {
        if (!prev.find(d => d.id === device.id)) {
          return [...prev, device];
        }
        return prev;
      });
    });
  }, []);

  const requestPermissions = async () => {
    if (Platform.OS === 'android') {
      await PermissionsAndroid.requestMultiple([
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
        PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
      ]);
    }
  };

  const scan = async () => {
    setStatus("Scanning...");
    setDevices([]);
    try {
      await BlufiClient.scan();
      setStatus("Scan Complete");
    } catch (e: any) {
      addLog("Scan Error: " + e.message);
    }
  };

  const connect = async (device: any) => {
    try {
      setStatus("Connecting to " + device.name);
      await BlufiClient.connect(device.id);
      setStatus("Connected");
      addLog("Connected to " + device.id);

      addLog("Negotiating Security...");
      await BlufiClient.negotiateSecurity();

    } catch (e: any) {
      addLog("Connection Error: " + e.message);
      setStatus("Error");
    }
  };

  const sendConfig = async () => {
    try {
      addLog("Sending Config...");

      // 1. Send IP
      await BlufiClient.postCustomData(`1:${mqttIp}`);
      addLog(`Sent IP: 1:${mqttIp}`);

      // 2. Send Port
      await BlufiClient.postCustomData(`2:1060`);
      addLog(`Sent Port: 2:1060`);

      // 3. Request UID
      await BlufiClient.postCustomData("12:");
      addLog("Sent UID Request (12:)");

      Alert.alert("Success", "Config Sent");
    } catch (e: any) {
      addLog("Send Error: " + e.message);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.header}>JS Blufi Tester</Text>
      <Text style={styles.status}>Status: {status}</Text>

      <Button title="Scan Devices" onPress={scan} />

      <ScrollView style={styles.deviceList}>
        {devices.map(d => (
          <TouchableOpacity key={d.id} style={styles.deviceItem} onPress={() => connect(d)}>
            <Text style={styles.deviceName}>{d.name || "Unknown"}</Text>
            <Text style={styles.deviceId}>{d.id}</Text>
          </TouchableOpacity>
        ))}
      </ScrollView>

      <View style={styles.configSection}>
        <TextInput
          style={styles.input}
          value={mqttIp}
          onChangeText={setMqttIp}
          placeholder="MQTT IP"
        />
        <Button title="Send Config" onPress={sendConfig} />
      </View>

      <ScrollView style={styles.logs}>
        {logs.map((l, i) => <Text key={i} style={styles.logText}>{l}</Text>)}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, paddingTop: 50 },
  header: { fontSize: 24, fontWeight: 'bold', marginBottom: 10 },
  status: { fontSize: 16, marginBottom: 10, color: 'blue' },
  deviceList: { maxHeight: 150, marginBottom: 20, borderWidth: 1, borderColor: '#eee' },
  deviceItem: { padding: 10, borderBottomWidth: 1, borderBottomColor: '#eee' },
  deviceName: { fontWeight: 'bold' },
  deviceId: { fontSize: 12, color: '#666' },
  configSection: { marginBottom: 20 },
  input: { borderWidth: 1, borderColor: '#ccc', padding: 10, marginBottom: 10, borderRadius: 5 },
  logs: { flex: 1, backgroundColor: '#000', padding: 10 },
  logText: { color: '#0f0', fontFamily: 'monospace', fontSize: 12 }
});
