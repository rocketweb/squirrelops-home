-- SquirrelOps Home: Marketing Screenshot Data (Complete Rebuild)
-- Run: cd sensor && sqlite3 data/squirrelops.db < scripts/seed_marketing_data.sql
-- Backup: data/squirrelops.db.bak
--
-- Builds a completely fictional smart home network from scratch.
-- Nothing here matches any real network.

PRAGMA foreign_keys = OFF;

-- ============================================================
-- WIPE ALL DATA TABLES
-- ============================================================

DELETE FROM canary_observations;
DELETE FROM decoy_connections;
DELETE FROM planted_credentials;
DELETE FROM security_insight_state;
DELETE FROM connection_baselines;
DELETE FROM device_open_ports;
DELETE FROM service_profiles;
DELETE FROM mimic_templates;
DELETE FROM virtual_ips;
DELETE FROM home_alerts;
DELETE FROM incidents;
DELETE FROM device_fingerprints;
DELETE FROM device_trust;
DELETE FROM decoys;
DELETE FROM events;
DELETE FROM devices;
-- NOTE: Do NOT wipe the pairing table — it contains real mTLS client
-- certificate fingerprints needed for the app to connect to the sensor.
-- DELETE FROM pairing;

-- Reset autoincrement counters
DELETE FROM sqlite_sequence;

PRAGMA foreign_keys = ON;

-- ============================================================
-- DEVICES (40 devices — a well-equipped suburban smart home)
-- ============================================================
-- Subnet: 192.168.100.0/24
-- All MACs use real OUI prefixes but fictional host bytes

INSERT INTO devices (id, ip_address, mac_address, hostname, vendor, device_type, model_name, area, custom_name, notes, is_online, first_seen, last_seen) VALUES
-- Infrastructure (1-5)
(1,  '192.168.100.1',   'FC:EC:DA:A1:37:02', 'omada-router.local',     'TP-Link',      'network_equipment', 'ER7206',            'Office',          'Omada Router',        NULL, 1, '2026-01-15T08:00:00Z', '2026-02-27T11:30:00Z'),
(2,  '192.168.100.2',   '78:8A:20:5C:9E:11', 'omada-ap-living',        'TP-Link',      'network_equipment', 'EAP670',            'Living Room',     'AP Living Room',      NULL, 1, '2026-01-15T08:05:00Z', '2026-02-27T11:30:00Z'),
(3,  '192.168.100.3',   '78:8A:20:5C:A2:44', 'omada-ap-upstairs',      'TP-Link',      'network_equipment', 'EAP610',            'Hallway',         'AP Upstairs',         NULL, 1, '2026-01-15T08:06:00Z', '2026-02-27T11:30:00Z'),
(4,  '192.168.100.4',   'D0:21:F9:7B:E3:90', 'omada-switch',           'TP-Link',      'network_equipment', 'TL-SG2218P',        'Basement',        'PoE Switch',          NULL, 1, '2026-01-15T08:07:00Z', '2026-02-27T11:30:00Z'),
(5,  '192.168.100.10',  '00:11:32:AB:CD:EF', 'asustor-nas',              'Asustor',         'nas',               'AS6704T',            'Basement',        'Asustor NAS',            'Plex, backups, surveillance', 1, '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),

-- Computers (6-9)
(6,  '192.168.100.20',  '3C:22:FB:19:A7:D5', 'Alexs-MacBook-Pro.local', 'Apple',       'computer',          'MacBook Pro 16"',   'Office',          'Alex''s MacBook Pro', NULL, 1, '2026-01-15T09:00:00Z', '2026-02-27T11:28:00Z'),
(7,  '192.168.100.21',  'A4:83:E7:62:1F:B8', 'Jess-MacBook-Air.local',  'Apple',       'computer',          'MacBook Air M3',    'Living Room',     'Jess''s MacBook Air', NULL, 1, '2026-01-15T09:15:00Z', '2026-02-27T10:45:00Z'),
(8,  '192.168.100.22',  '8C:AA:B5:04:E2:71', 'DESKTOP-GAMING',          'Samsung',     'computer',          'Odyssey Tower',     'Basement',        'Gaming PC',           NULL, 1, '2026-01-20T14:00:00Z', '2026-02-27T01:30:00Z'),
(9,  '192.168.100.23',  'DC:A6:32:7F:14:C3', 'hubitat.local',           'Hubitat',     'smart_home',        'Elevation C-8 Pro', 'Basement',        'Hubitat Hub',         'Smart home automation hub', 1, '2026-01-16T11:00:00Z', '2026-02-27T11:30:00Z'),

-- Mobile devices (10-14)
(10, '192.168.100.30',  '1C:1D:D3:8A:55:02', 'Alexs-iPhone.local',      'Apple',       'smartphone',        'iPhone 16 Pro',     NULL,              'Alex''s iPhone',      NULL, 1, '2026-01-15T08:30:00Z', '2026-02-27T11:25:00Z'),
(11, '192.168.100.31',  'F0:18:98:CC:47:19', 'Jess-iPhone.local',       'Apple',       'smartphone',        'iPhone 15',         NULL,              'Jess''s iPhone',      NULL, 1, '2026-01-15T08:35:00Z', '2026-02-27T11:20:00Z'),
(12, '192.168.100.32',  '64:E8:81:3D:BC:A0', NULL,                      'Samsung',     'smartphone',        'Galaxy S24',        NULL,              'Guest Phone',         NULL, 0, '2026-02-22T18:00:00Z', '2026-02-22T23:15:00Z'),
(13, '192.168.100.33',  '3C:22:FB:41:D8:EE', 'Alexs-iPad.local',        'Apple',       'computer',          'iPad Pro 13"',      'Living Room',     'iPad Pro',            NULL, 1, '2026-01-18T19:00:00Z', '2026-02-27T09:00:00Z'),
(14, '192.168.100.34',  'F0:18:98:1B:62:A4', NULL,                      'Apple',       'computer',          'Apple Watch',       NULL,              'Alex''s Watch',       NULL, 1, '2026-01-15T08:31:00Z', '2026-02-27T11:25:00Z'),

-- TVs & Streaming (15-18)
(15, '192.168.100.40',  '8C:AA:B5:71:FE:33', 'LG-OLED-TV',              'LG',          'smart_tv',          'OLED G4 65"',       'Living Room',     'Living Room TV',      NULL, 1, '2026-01-17T15:00:00Z', '2026-02-27T03:00:00Z'),
(16, '192.168.100.41',  'A8:23:FE:D9:41:07', 'Sony-TV-Basement',        'Sony',        'smart_tv',          'Bravia XR A95L',    'Basement',        'Basement TV',         NULL, 1, '2026-01-20T14:30:00Z', '2026-02-26T23:45:00Z'),
(17, '192.168.100.42',  '3C:22:FB:88:AC:6D', 'Apple-TV.local',          'Apple',       'streaming',         'Apple TV 4K',       'Living Room',     'Apple TV',            NULL, 1, '2026-01-17T15:30:00Z', '2026-02-27T03:00:00Z'),
(18, '192.168.100.43',  '7C:BB:8A:E1:02:5F', NULL,                      'Nintendo',    'gaming_console',    'Switch OLED',       'Basement',        'Nintendo Switch',     NULL, 1, '2026-02-01T10:00:00Z', '2026-02-26T20:30:00Z'),

-- Speakers (19-23)
(19, '192.168.100.50',  '94:9F:3E:D7:22:A1', 'Living-Room.local',       'KEF',         'speaker',           'LS60 Wireless',     'Living Room',     'KEF Living Room',     NULL, 1, '2026-01-17T16:00:00Z', '2026-02-27T11:30:00Z'),
(20, '192.168.100.51',  '48:A6:B8:3E:F5:19', 'Kitchen.local',           'KEF',         'speaker',           'LSX II LT',         'Kitchen',         'KEF Kitchen',         NULL, 1, '2026-01-17T16:05:00Z', '2026-02-27T11:30:00Z'),
(21, '192.168.100.52',  '94:9F:3E:D7:34:BB', 'Bedroom.local',           'KEF',         'speaker',           'LSX II',            'Master Bedroom',  'KEF Bedroom',         NULL, 1, '2026-01-17T16:10:00Z', '2026-02-27T11:30:00Z'),
(22, '192.168.100.53',  '3C:22:FB:C1:97:40', 'HomePod-Office.local',    'Apple',       'smart_speaker',     'HomePod mini',      'Office',          'HomePod mini',        NULL, 1, '2026-01-18T09:00:00Z', '2026-02-27T11:30:00Z'),
(23, '192.168.100.54',  '74:C2:46:8B:D1:53', 'Echo-Kids.local',         'Amazon',      'smart_speaker',     'Echo Dot 5th Gen',  'Kids'' Room',     'Echo Dot',            NULL, 1, '2026-01-19T10:00:00Z', '2026-02-27T11:30:00Z'),

-- Smart Home Hubs & Sensors (24-28)
(24, '192.168.100.60',  '00:17:88:A4:E3:72', 'lutron-bridge.local',     'Lutron',      'smart_home',        'Caseta Smart Bridge Pro', 'Hallway',   'Lutron Bridge',       '14 lights connected', 1, '2026-01-16T12:00:00Z', '2026-02-27T11:30:00Z'),
(25, '192.168.100.61',  '44:61:32:9C:B7:15', 'nest-thermostat',         'Google',      'thermostat',        'Nest Learning 4th Gen', 'Hallway',   'Nest Thermostat',     NULL, 1, '2026-01-16T13:00:00Z', '2026-02-27T11:30:00Z'),
(26, '192.168.100.62',  '7C:2C:67:1A:DE:08', 'esp-plant-kitchen',       'Espressif',   'iot_device',        'ESP32-S3',          'Kitchen',         'Plant Sensor Kitchen', NULL, 1, '2026-02-05T09:00:00Z', '2026-02-27T11:00:00Z'),
(27, '192.168.100.63',  '7C:2C:67:2B:F1:99', 'esp-plant-office',        'Espressif',   'iot_device',        'ESP32-S3',          'Office',          'Plant Sensor Office',  NULL, 1, '2026-02-05T09:05:00Z', '2026-02-27T11:00:00Z'),
(28, '192.168.100.64',  '50:14:79:88:C4:3A', 'roborock-s8',             'Roborock',    'smart_home',        'S8 MaxV Ultra',     'Living Room',     'Robot Vacuum',        NULL, 1, '2026-01-22T11:00:00Z', '2026-02-27T08:30:00Z'),

-- Security Cameras & Locks (29-32)
(29, '192.168.100.70',  '4C:B9:EA:55:A3:D1', 'eufy-doorbell',           'Eufy',        'camera',            'Video Doorbell Dual','Front Porch',    'Front Doorbell',      NULL, 1, '2026-01-16T14:00:00Z', '2026-02-27T11:30:00Z'),
(30, '192.168.100.71',  '4C:B9:EA:55:B8:22', 'eufy-floodlight',         'Eufy',        'camera',            'Floodlight Cam E340','Backyard',       'Backyard Floodlight', NULL, 1, '2026-01-16T14:30:00Z', '2026-02-27T11:30:00Z'),
(31, '192.168.100.72',  '9C:B7:0D:4E:91:F7', 'reolink-garage',          'Reolink',     'camera',            'RLC-810A',          'Garage',          'Garage Camera',       NULL, 1, '2026-01-18T10:00:00Z', '2026-02-27T11:30:00Z'),
(32, '192.168.100.75',  'E8:FA:F6:2C:DD:18', 'august-lock',             'August',      'smart_home',        'Wi-Fi Smart Lock',  'Front Porch',     'Front Door Lock',     NULL, 1, '2026-01-16T15:00:00Z', '2026-02-27T11:30:00Z'),

-- Appliances & Other (33-36)
(33, '192.168.100.80',  '3C:D9:2B:F4:11:63', 'HP-LaserJet.local',       'HP',          'computer',          'LaserJet Pro M404n','Office',          'Office Printer',      NULL, 1, '2026-01-17T08:00:00Z', '2026-02-27T09:15:00Z'),
(34, '192.168.100.81',  'B0:4A:39:CE:8F:27', 'levoit-purifier',         'Levoit',      'smart_home',        'Core 600S',        'Master Bedroom',   'Air Purifier',        NULL, 1, '2026-01-25T20:00:00Z', '2026-02-27T11:30:00Z'),
(35, '192.168.100.90',  'F8:46:1C:D2:7A:B5', NULL,                      'Sony',        'gaming_console',    'PlayStation 5',     'Basement',        'PS5',                 NULL, 1, '2026-01-20T15:00:00Z', '2026-02-26T22:00:00Z'),
(36, '192.168.100.91',  'E4:FA:C4:3A:82:CC', 'myq-garage',              'Chamberlain', 'smart_home',        'myQ Smart Garage',  'Garage',          'Garage Door Opener',  NULL, 1, '2026-01-22T14:00:00Z', '2026-02-27T11:30:00Z'),

-- Smart Lights (TP-Link Kasa) (37-39)
(37, '192.168.100.95',  'E4:FA:C4:B1:29:D4', 'kasa-porch',              'TP-Link',     'smart_lighting',    'Kasa KL135',        'Front Porch',     'Porch Light',         NULL, 1, '2026-01-22T15:00:00Z', '2026-02-27T11:30:00Z'),
(38, '192.168.100.96',  'E4:FA:C4:B1:3D:87', 'kasa-garage',             'TP-Link',     'smart_lighting',    'Kasa KL135',        'Garage',          'Garage Light',        NULL, 1, '2026-01-22T15:05:00Z', '2026-02-27T11:30:00Z'),
(39, '192.168.100.97',  'E4:FA:C4:B1:4A:F0', 'kasa-basement',           'TP-Link',     'smart_lighting',    'Kasa KL135',        'Basement',        'Basement Light',      NULL, 1, '2026-01-22T15:10:00Z', '2026-02-27T11:30:00Z'),

-- Suspicious / unreviewed devices (40-43)
(40, '192.168.100.150', '2A:F1:9C:33:DD:07', NULL,                      NULL,          'unknown',           NULL,                NULL,              NULL,                  NULL, 1, '2026-02-27T06:14:00Z', '2026-02-27T11:30:00Z'),
(41, '192.168.100.151', 'CA:8E:22:7B:11:95', NULL,                      NULL,          'unknown',           NULL,                NULL,              NULL,                  NULL, 1, '2026-02-27T08:42:00Z', '2026-02-27T11:10:00Z'),
(42, '192.168.100.199', '08:00:27:3F:C8:A1', NULL,                      'Oracle',      'unknown',           NULL,                NULL,              NULL,                  'VirtualBox OUI — possible VM', 0, '2026-02-26T02:33:00Z', '2026-02-26T04:17:00Z'),
(43, '192.168.100.168', 'B4:2E:99:51:F3:DC', 'android-abc123def',       'Google',      'smartphone',        NULL,                NULL,              NULL,                  NULL, 0, '2026-02-23T19:00:00Z', '2026-02-23T22:30:00Z');


-- ============================================================
-- DEVICE TRUST
-- ============================================================

INSERT INTO device_trust (device_id, status, approved_by, updated_at) VALUES
-- Infrastructure — all approved
(1,  'approved', 'user', '2026-01-15T08:10:00Z'),
(2,  'approved', 'user', '2026-01-15T08:10:00Z'),
(3,  'approved', 'user', '2026-01-15T08:10:00Z'),
(4,  'approved', 'user', '2026-01-15T08:10:00Z'),
(5,  'approved', 'user', '2026-01-16T10:30:00Z'),
-- Computers
(6,  'approved', 'user', '2026-01-15T09:10:00Z'),
(7,  'approved', 'user', '2026-01-15T09:20:00Z'),
(8,  'approved', 'user', '2026-01-20T14:30:00Z'),
(9,  'approved', 'user', '2026-01-16T11:30:00Z'),
-- Mobile
(10, 'approved', 'user', '2026-01-15T08:40:00Z'),
(11, 'approved', 'user', '2026-01-15T08:45:00Z'),
(12, 'approved', 'user', '2026-02-22T18:30:00Z'),
(13, 'approved', 'user', '2026-01-18T19:30:00Z'),
(14, 'approved', 'user', '2026-01-15T08:40:00Z'),
-- TVs & Streaming
(15, 'approved', 'user', '2026-01-17T15:15:00Z'),
(16, 'approved', 'user', '2026-01-20T14:45:00Z'),
(17, 'approved', 'user', '2026-01-17T15:45:00Z'),
(18, 'approved', 'user', '2026-02-01T10:30:00Z'),
-- Speakers
(19, 'approved', 'user', '2026-01-17T16:15:00Z'),
(20, 'approved', 'user', '2026-01-17T16:15:00Z'),
(21, 'approved', 'user', '2026-01-17T16:15:00Z'),
(22, 'approved', 'user', '2026-01-18T09:15:00Z'),
(23, 'approved', 'user', '2026-01-19T10:15:00Z'),
-- Smart Home
(24, 'approved', 'user', '2026-01-16T12:15:00Z'),
(25, 'approved', 'user', '2026-01-16T13:15:00Z'),
(26, 'approved', 'user', '2026-02-05T09:15:00Z'),
(27, 'approved', 'user', '2026-02-05T09:15:00Z'),
(28, 'approved', 'user', '2026-01-22T11:15:00Z'),
-- Security
(29, 'approved', 'user', '2026-01-16T14:15:00Z'),
(30, 'approved', 'user', '2026-01-16T14:45:00Z'),
(31, 'approved', 'user', '2026-01-18T10:15:00Z'),
(32, 'approved', 'user', '2026-01-16T15:15:00Z'),
-- Appliances
(33, 'approved', 'user', '2026-01-17T08:15:00Z'),
(34, 'approved', 'user', '2026-01-25T20:15:00Z'),
(35, 'approved', 'user', '2026-01-20T15:15:00Z'),
(36, 'approved', 'user', '2026-01-22T14:15:00Z'),
-- Lights
(37, 'approved', 'user', '2026-01-22T15:15:00Z'),
(38, 'approved', 'user', '2026-01-22T15:15:00Z'),
(39, 'approved', 'user', '2026-01-22T15:15:00Z'),
-- Suspicious — rejected
(42, 'rejected', 'user', '2026-02-26T08:00:00Z'),
-- Unreviewed
(40, 'unknown', NULL, '2026-02-27T06:14:00Z'),
(41, 'unknown', NULL, '2026-02-27T08:42:00Z'),
(43, 'unknown', NULL, '2026-02-23T19:00:00Z');


-- ============================================================
-- DEVICE OPEN PORTS (key devices)
-- ============================================================

INSERT INTO device_open_ports (device_id, port, protocol, service_name, banner, first_seen, last_seen) VALUES
-- Router
(1,  22,   'tcp', 'SSH',    'SSH-2.0-OpenSSH_8.9',                     '2026-01-15T08:00:00Z', '2026-02-27T11:30:00Z'),
(1,  80,   'tcp', 'HTTP',   'TP-Link/1.0',                             '2026-01-15T08:00:00Z', '2026-02-27T11:30:00Z'),
(1,  443,  'tcp', 'HTTPS',  NULL,                                       '2026-01-15T08:00:00Z', '2026-02-27T11:30:00Z'),
-- NAS
(5,  22,   'tcp', 'SSH',    'SSH-2.0-OpenSSH_9.0',                     '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
(5,  80,   'tcp', 'HTTP',   'nginx',                                    '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
(5,  443,  'tcp', 'HTTPS',  'nginx',                                    '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
(5,  5000, 'tcp', 'ADM',    'Asustor ADM',                                '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
(5,  5001, 'tcp', 'ADM-SSL','Asustor ADM (HTTPS)',                        '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
(5,  445,  'tcp', 'SMB',    NULL,                                       '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
(5,  32400,'tcp', 'Plex',   'Plex Media Server',                        '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
-- Hubitat Hub
(9,  8081, 'tcp', 'HTTP',   'Hubitat/2.4.1',                           '2026-01-16T11:00:00Z', '2026-02-27T11:30:00Z'),
(9,  22,   'tcp', 'SSH',    'SSH-2.0-OpenSSH_9.6',                     '2026-01-16T11:00:00Z', '2026-02-27T11:30:00Z'),
-- Printer
(33, 80,   'tcp', 'HTTP',   'HP HTTP Server',                           '2026-01-17T08:00:00Z', '2026-02-27T09:15:00Z'),
(33, 443,  'tcp', 'HTTPS',  'HP HTTP Server',                           '2026-01-17T08:00:00Z', '2026-02-27T09:15:00Z'),
(33, 631,  'tcp', 'IPP',    NULL,                                       '2026-01-17T08:00:00Z', '2026-02-27T09:15:00Z'),
(33, 9100, 'tcp', 'RAW',    'HP JetDirect',                             '2026-01-17T08:00:00Z', '2026-02-27T09:15:00Z'),
-- TV
(15, 8001, 'tcp', 'HTTP',   'LG Smart TV',                              '2026-01-17T15:00:00Z', '2026-02-27T03:00:00Z'),
(15, 8002, 'tcp', 'HTTPS',  NULL,                                       '2026-01-17T15:00:00Z', '2026-02-27T03:00:00Z'),
-- PS5
(35, 987,  'tcp', 'PS Remote','PlayStation Remote Play',                 '2026-01-20T15:00:00Z', '2026-02-26T22:00:00Z'),
(35, 9295, 'tcp', 'PS Remote','PlayStation Second Screen',               '2026-01-20T15:00:00Z', '2026-02-26T22:00:00Z'),
-- Suspicious VM device had open ports
(42, 22,   'tcp', 'SSH',    'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5', '2026-02-26T02:33:00Z', '2026-02-26T04:17:00Z'),
(42, 80,   'tcp', 'HTTP',   'Apache/2.4.41 (Ubuntu)',                   '2026-02-26T02:33:00Z', '2026-02-26T04:17:00Z'),
(42, 8080, 'tcp', 'HTTP',   'Werkzeug/2.3.7 Python/3.10.12',           '2026-02-26T02:33:00Z', '2026-02-26T04:17:00Z'),
(42, 445,  'tcp', 'SMB',    NULL,                                       '2026-02-26T02:33:00Z', '2026-02-26T04:17:00Z'),
(42, 3389, 'tcp', 'RDP',    NULL,                                       '2026-02-26T02:33:00Z', '2026-02-26T04:17:00Z');


-- ============================================================
-- DECOYS (3 standard honeypots + 10 mimic decoys)
-- ============================================================

INSERT INTO decoys (id, name, decoy_type, bind_address, port, status, config, connection_count, credential_trip_count, failure_count, last_failure_at, created_at, updated_at) VALUES
-- Standard honeypots
(1,  'Dev Server',     'dev_server',      '0.0.0.0', 51874, 'active',  '{"banner": "Express/4.18.2"}',          4, 1, 0, NULL, '2026-01-20T09:00:00Z', '2026-02-27T09:42:00Z'),
(2,  'Smart Hub',      'home_assistant',  '0.0.0.0', 51875, 'active',  '{"banner": "Hubitat/2.4.1"}',           3, 0, 0, NULL, '2026-01-20T09:05:00Z', '2026-02-25T03:16:00Z'),
(3,  'Network Share',  'file_share',      '0.0.0.0', 51876, 'active',  '{"banner": "Samba 4.18", "password_filename": "passwords.txt"}', 5, 2, 0, NULL, '2026-01-20T09:10:00Z', '2026-02-27T09:48:00Z'),

-- Mimic decoys (cloned from real devices via Squirrel Scouts)
(4,  'Mimic: Omada Router',      'mimic', '192.168.100.200', 80,   'active', NULL, 2, 0, 0, NULL, '2026-02-18T12:00:00Z', '2026-02-27T09:40:00Z'),
(5,  'Mimic: Asustor NAS',          'mimic', '192.168.100.201', 5001, 'active', NULL, 3, 0, 0, NULL, '2026-02-18T12:05:00Z', '2026-02-27T11:00:00Z'),
(6,  'Mimic: Hubitat Hub',        'mimic', '192.168.100.202', 8081, 'active', NULL, 1, 0, 0, NULL, '2026-02-18T12:10:00Z', '2026-02-27T03:20:00Z'),
(7,  'Mimic: HP Printer',         'mimic', '192.168.100.203', 80,   'active', NULL, 1, 0, 0, NULL, '2026-02-18T12:15:00Z', '2026-02-27T09:15:00Z'),
(8,  'Mimic: LG TV',              'mimic', '192.168.100.204', 8001, 'active', NULL, 0, 0, 0, NULL, '2026-02-18T12:20:00Z', '2026-02-18T12:20:00Z'),
(9,  'Mimic: Eufy Doorbell',     'mimic', '192.168.100.205', 443,  'active', NULL, 0, 0, 0, NULL, '2026-02-18T12:25:00Z', '2026-02-18T12:25:00Z'),
(10, 'Mimic: Nest Thermostat',    'mimic', '192.168.100.206', 443,  'active', NULL, 0, 0, 0, NULL, '2026-02-18T12:30:00Z', '2026-02-18T12:30:00Z'),
(11, 'Mimic: Plex Server',        'mimic', '192.168.100.207', 32400,'active', NULL, 1, 0, 0, NULL, '2026-02-18T12:35:00Z', '2026-02-27T02:45:00Z'),
(12, 'Mimic: PS5 Remote',         'mimic', '192.168.100.208', 987,  'active', NULL, 0, 0, 0, NULL, '2026-02-18T12:40:00Z', '2026-02-18T12:40:00Z'),
(13, 'Mimic: MacBook Pro',        'mimic', '192.168.100.209', 5000, 'active', NULL, 0, 0, 0, NULL, '2026-02-18T12:45:00Z', '2026-02-18T12:45:00Z');


-- ============================================================
-- VIRTUAL IPS (mimic allocations)
-- ============================================================

INSERT INTO virtual_ips (ip_address, interface, decoy_id, created_at) VALUES
('192.168.100.200', 'en0', 4,  '2026-02-18T12:00:00Z'),
('192.168.100.201', 'en0', 5,  '2026-02-18T12:05:00Z'),
('192.168.100.202', 'en0', 6,  '2026-02-18T12:10:00Z'),
('192.168.100.203', 'en0', 7,  '2026-02-18T12:15:00Z'),
('192.168.100.204', 'en0', 8,  '2026-02-18T12:20:00Z'),
('192.168.100.205', 'en0', 9,  '2026-02-18T12:25:00Z'),
('192.168.100.206', 'en0', 10, '2026-02-18T12:30:00Z'),
('192.168.100.207', 'en0', 11, '2026-02-18T12:35:00Z'),
('192.168.100.208', 'en0', 12, '2026-02-18T12:40:00Z'),
('192.168.100.209', 'en0', 13, '2026-02-18T12:45:00Z');


-- ============================================================
-- PLANTED CREDENTIALS (across the 3 standard decoys)
-- ============================================================

INSERT INTO planted_credentials (id, credential_type, credential_value, canary_hostname, planted_location, decoy_id, tripped, first_tripped_at, created_at) VALUES
-- Dev Server decoy
(1,  'env_file',         'AWS_ACCESS_KEY_ID=AKIAX9EXAMPLE2DEMO01\nAWS_SECRET_ACCESS_KEY=wJalrXExAmPlEkEy/bPxRfiCYDEMOKEY01', NULL, '.env',           1, 1, '2026-02-27T09:42:30Z', '2026-01-20T09:00:00Z'),
(2,  'github_pat',       'ghp_d3m0ExAmPlEt0k3nF0rScr33nSh0ts99',                                                              NULL, '.env',           1, 0, NULL,                   '2026-01-20T09:00:00Z'),
(3,  'db_connection',    'postgresql://admin:s3cur3p4ss@db.internal:5432/production',                                           NULL, '.env',           1, 0, NULL,                   '2026-01-20T09:00:00Z'),
-- Smart Hub decoy
(4,  'ha_token',         'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.DEMO.TOKEN',                                                   NULL, 'config/.storage', 2, 0, NULL,                   '2026-01-20T09:05:00Z'),
(5,  'generic_password', 'admin:smarthub2026',                                                                                  NULL, 'config/.storage', 2, 0, NULL,                   '2026-01-20T09:05:00Z'),
-- File Share decoy
(6,  'ssh_key',          '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAADEMO\n-----END OPENSSH PRIVATE KEY-----', NULL, 'id_rsa',          3, 1, '2026-02-27T09:47:00Z', '2026-01-20T09:10:00Z'),
(7,  'aws_key',          'AKIAX9EXAMPLE2DEMO02 / wJalrXExAmPlEkEy/bPxRfiCYDEMOKEY02',                                          NULL, 'passwords.txt',   3, 1, '2026-02-27T09:48:00Z', '2026-01-20T09:10:00Z'),
(8,  'generic_password', 'admin:P@ssw0rd123!',                                                                                  NULL, 'passwords.txt',   3, 0, NULL,                   '2026-01-20T09:10:00Z'),
(9,  'generic_password', 'root:toor',                                                                                           NULL, 'passwords.txt',   3, 0, NULL,                   '2026-01-20T09:10:00Z'),
(10, 'generic_password', 'nas_backup:Asust0r!2026',                                                                                NULL, 'passwords.txt',   3, 0, NULL,                   '2026-01-20T09:10:00Z'),
(11, 'env_file',         'DATABASE_URL=mysql://root:r00tpass@localhost/app',                                                     NULL, 'passwords.txt',   3, 0, NULL,                   '2026-01-20T09:10:00Z'),
(12, 'generic_password', 'jsmith:Winter2026!',                                                                                   NULL, 'passwords.txt',   3, 0, NULL,                   '2026-01-20T09:10:00Z');


-- ============================================================
-- INCIDENTS
-- ============================================================

-- Incident 1: ACTIVE — VM device scanning and stealing credentials
INSERT INTO incidents (id, source_ip, source_mac, status, severity, alert_count, first_alert_at, last_alert_at, summary)
VALUES (1, '192.168.100.199', '08:00:27:3F:C8:A1', 'active', 'critical', 4,
        '2026-02-26T02:33:00Z', '2026-02-27T09:48:00Z',
        'Unrecognized VM accessed multiple honeypots and exfiltrated planted credentials');

-- Incident 2: CLOSED — overnight probe from guest phone
INSERT INTO incidents (id, source_ip, source_mac, status, severity, alert_count, first_alert_at, last_alert_at, closed_at, summary)
VALUES (2, '192.168.100.168', 'B4:2E:99:51:F3:DC', 'closed', 'high', 2,
        '2026-02-23T19:15:00Z', '2026-02-23T19:22:00Z', '2026-02-24T09:00:00Z',
        'Guest device probed Smart Hub and File Share honeypots');

-- Incident 3: ACTIVE — unknown device with risky ports
INSERT INTO incidents (id, source_ip, source_mac, status, severity, alert_count, first_alert_at, last_alert_at, summary)
VALUES (3, '192.168.100.150', '2A:F1:9C:33:DD:07', 'active', 'medium', 1,
        '2026-02-27T06:14:00Z', '2026-02-27T06:14:00Z',
        'Unreviewed device appeared on network');


-- ============================================================
-- ALERTS (diverse, realistic, marketing-worthy)
-- ============================================================

INSERT INTO home_alerts (id, incident_id, alert_type, severity, title, detail, source_ip, source_mac, device_id, decoy_id, read_at, actioned_at, action_note, created_at) VALUES

-- CRITICAL: Credential trip — VM stole AWS key from file share (incident 1)
(1,  1, 'decoy.credential_trip', 'critical',
     'Planted AWS Key Accessed',
     '{"source_ip": "192.168.100.199", "source_port": 49221, "dest_port": 445, "protocol": "tcp", "credential_used": "AKIAX9EXAMPLE2DEMO02", "request_path": "/share/passwords.txt", "timestamp": "2026-02-27T09:48:00Z", "detection_method": "decoy_http"}',
     '192.168.100.199', '08:00:27:3F:C8:A1', 42, 3, NULL, NULL, NULL,
     '2026-02-27T09:48:00Z'),

-- CRITICAL: Credential trip — VM stole .env from dev server (incident 1)
(2,  1, 'decoy.credential_trip', 'critical',
     'Planted .env File Downloaded',
     '{"source_ip": "192.168.100.199", "source_port": 49218, "dest_port": 8080, "protocol": "http", "credential_used": "AKIAX9EXAMPLE2DEMO01", "request_path": "/debug/.env", "timestamp": "2026-02-27T09:42:30Z", "detection_method": "decoy_http"}',
     '192.168.100.199', '08:00:27:3F:C8:A1', 42, 1, NULL, NULL, NULL,
     '2026-02-27T09:42:30Z'),

-- HIGH: Decoy trip — VM browsed file share (incident 1)
(3,  1, 'decoy.trip', 'high',
     'Honeypot File Share Browsed',
     '{"source_ip": "192.168.100.199", "source_port": 49220, "dest_port": 445, "protocol": "tcp", "request_path": "/share/", "timestamp": "2026-02-27T09:45:00Z"}',
     '192.168.100.199', '08:00:27:3F:C8:A1', 42, 3, NULL, NULL, NULL,
     '2026-02-27T09:45:00Z'),

-- HIGH: Decoy trip — VM probed dev server (incident 1)
(4,  1, 'decoy.trip', 'high',
     'Honeypot Dev Server Scanned',
     '{"source_ip": "192.168.100.199", "source_port": 49217, "dest_port": 8080, "protocol": "http", "request_path": "/debug/vars", "timestamp": "2026-02-27T09:40:00Z"}',
     '192.168.100.199', '08:00:27:3F:C8:A1', 42, 1, NULL, NULL, NULL,
     '2026-02-27T09:40:00Z'),

-- HIGH: Decoy trip — guest device hit Smart Hub honeypot (incident 2, closed)
(5,  2, 'decoy.trip', 'high',
     'Honeypot Smart Hub Probed',
     '{"source_ip": "192.168.100.168", "source_port": 52100, "dest_port": 8081, "protocol": "http", "request_path": "/hub/advanced", "timestamp": "2026-02-23T19:15:00Z"}',
     '192.168.100.168', 'B4:2E:99:51:F3:DC', 43, 2,
     '2026-02-24T07:30:00Z', '2026-02-24T09:00:00Z', 'Identified as a friend''s phone running a network scanning app. Talked to them about it.',
     '2026-02-23T19:15:00Z'),

-- HIGH: Decoy trip — guest device hit file share (incident 2, closed)
(6,  2, 'decoy.trip', 'high',
     'Honeypot File Share Probed',
     '{"source_ip": "192.168.100.168", "source_port": 52105, "dest_port": 445, "protocol": "tcp", "request_path": "/share/", "timestamp": "2026-02-23T19:22:00Z"}',
     '192.168.100.168', 'B4:2E:99:51:F3:DC', 43, 3,
     '2026-02-24T07:30:00Z', '2026-02-24T09:00:00Z', 'Same device — resolved.',
     '2026-02-23T19:22:00Z'),

-- HIGH: MAC address changed on unknown device
(7,  NULL, 'device.mac_changed', 'high',
     'MAC Address Changed on 192.168.100.150',
     'Device MAC changed from 1E:AA:07:CC:D9:55 to 2A:F1:9C:33:DD:07 — possible MAC randomization or device spoofing.',
     '192.168.100.150', '2A:F1:9C:33:DD:07', 40, NULL,
     NULL, NULL, NULL,
     '2026-02-27T06:15:00Z'),

-- HIGH: SMB on Asustor NAS (real device, useful port risk)
(8,  NULL, 'security.port_risk', 'high',
     'SMB File Sharing Open on Asustor NAS',
     '{"device_id": 5, "port": 445, "service_name": "SMB file sharing", "risk_description": "Windows file sharing (SMB/CIFS) is exposed on the network. SMB has a history of critical vulnerabilities including EternalBlue. Ensure SMB signing is enabled and restrict access.", "remediation_steps": "Enable SMB signing in ADM settings and restrict access to specific IPs via the Asustor firewall"}',
     '192.168.100.10', '00:11:32:AB:CD:EF', 5, NULL,
     NULL, NULL, NULL,
     '2026-02-27T08:00:00Z'),

-- MEDIUM: New device alerts for unknown devices (incident 3)
(9,  3, 'device.new', 'medium',
     'New Device Discovered',
     'New device appeared at 192.168.100.150 with MAC 2A:F1:9C:33:DD:07. No vendor identified. Device has not been seen before.',
     '192.168.100.150', '2A:F1:9C:33:DD:07', 40, NULL,
     NULL, NULL, NULL,
     '2026-02-27T06:14:00Z'),

(10, NULL, 'device.new', 'medium',
     'New Device Discovered',
     'New device appeared at 192.168.100.151 with MAC CA:8E:22:7B:11:95. No vendor identified.',
     '192.168.100.151', 'CA:8E:22:7B:11:95', 41, NULL,
     NULL, NULL, NULL,
     '2026-02-27T08:42:00Z'),

-- MEDIUM: Behavioral anomaly — robot vacuum phoning home to unusual endpoint
(11, NULL, 'behavioral.anomaly', 'medium',
     'Unusual Outbound Connection from Robot Vacuum',
     'Device contacted 54.210.167.99:8883 (cn: telemetry.roborock.com) on an unusual port not observed during the learning period.',
     '192.168.100.64', '50:14:79:88:C4:3A', 28, NULL,
     '2026-02-27T10:00:00Z', NULL, NULL,
     '2026-02-27T07:30:00Z'),

-- MEDIUM: Behavioral anomaly — Echo Dot
(12, NULL, 'behavioral.anomaly', 'medium',
     'Unexpected DNS Query from Echo Dot',
     'Device resolved api.amazonalexa.com via non-standard DNS server 8.8.8.8 instead of the local resolver — possible DNS configuration change.',
     '192.168.100.54', '74:C2:46:8B:D1:53', 23, NULL,
     NULL, NULL, NULL,
     '2026-02-27T09:15:00Z'),

-- MEDIUM: Port risk on printer
(13, NULL, 'security.port_risk', 'medium',
     'RAW Printing Port Open on Office Printer',
     '{"device_id": 33, "port": 9100, "service_name": "JetDirect RAW printing", "risk_description": "Port 9100 allows direct printing without authentication. An attacker on the network could send arbitrary print jobs or potentially exploit printer firmware.", "remediation_steps": "Disable JetDirect RAW printing in printer settings and use IPP (port 631) with authentication instead"}',
     '192.168.100.80', '3C:D9:2B:F4:11:63', 33, NULL,
     '2026-02-26T10:00:00Z', NULL, NULL,
     '2026-02-26T08:15:00Z'),

-- MEDIUM: Verification needed for new device
(14, NULL, 'device.verification_needed', 'medium',
     'Device Verification Needed',
     'Device at 192.168.100.151 uses a randomized MAC address (CA:8E:22:7B:11:95) and cannot be reliably identified. Manual verification recommended.',
     '192.168.100.151', 'CA:8E:22:7B:11:95', 41, NULL,
     NULL, NULL, NULL,
     '2026-02-27T08:43:00Z'),

-- LOW: Learning complete (old, read)
(15, NULL, 'system.learning_complete', 'low',
     '48-Hour Learning Period Complete',
     'SquirrelOps has finished its 48-hour learning period and established behavioral baselines for 39 devices across your network.',
     NULL, NULL, NULL, NULL,
     '2026-01-17T08:00:00Z', NULL, NULL,
     '2026-01-17T08:00:00Z'),

-- LOW: Review reminder
(16, NULL, 'device.review_reminder', 'low',
     'Devices Awaiting Review',
     '2 devices discovered more than 24 hours ago have not been approved or rejected. Review them in the device inventory.',
     NULL, NULL, NULL, NULL,
     '2026-02-27T10:00:00Z', NULL, NULL,
     '2026-02-27T08:00:00Z'),

-- MEDIUM: VM device port risk (adds to the story)
(17, NULL, 'security.port_risk', 'high',
     'RDP Open on Unrecognized Device',
     '{"device_id": 42, "port": 3389, "service_name": "Remote Desktop Protocol", "risk_description": "RDP is exposed on an unrecognized device running a VirtualBox VM. RDP is frequently targeted by brute-force attacks and has had multiple critical vulnerabilities.", "remediation_steps": "Investigate this device immediately. If unauthorized, remove it from the network and check for lateral movement."}',
     '192.168.100.199', '08:00:27:3F:C8:A1', 42, NULL,
     '2026-02-26T08:00:00Z', '2026-02-26T08:00:00Z', 'Rejected device. Monitoring via decoys.',
     '2026-02-26T02:35:00Z'),

-- HIGH: Mimic decoy connection detected
(18, NULL, 'decoy.trip', 'high',
     'Mimic NAS Decoy Probed',
     '{"source_ip": "192.168.100.199", "source_port": 49250, "dest_port": 5001, "protocol": "https", "request_path": "/cgi-bin/authLogin.cgi", "timestamp": "2026-02-27T09:38:00Z"}',
     '192.168.100.199', '08:00:27:3F:C8:A1', 42, 5,
     NULL, NULL, NULL,
     '2026-02-27T09:38:00Z');


-- ============================================================
-- DECOY CONNECTIONS
-- ============================================================

INSERT INTO decoy_connections (decoy_id, source_ip, source_mac, port, protocol, request_path, credential_used, timestamp) VALUES
-- VM device (42) hitting multiple decoys
(1, '192.168.100.199', '08:00:27:3F:C8:A1', 8080, 'http',  '/debug/vars', NULL,                     '2026-02-27T09:40:00Z'),
(1, '192.168.100.199', '08:00:27:3F:C8:A1', 8080, 'http',  '/debug/.env', 'AKIAX9EXAMPLE2DEMO01',   '2026-02-27T09:42:30Z'),
(3, '192.168.100.199', '08:00:27:3F:C8:A1', 445,  'tcp',   '/share/',     NULL,                     '2026-02-27T09:45:00Z'),
(3, '192.168.100.199', '08:00:27:3F:C8:A1', 445,  'tcp',   '/share/id_rsa', NULL,                   '2026-02-27T09:46:30Z'),
(3, '192.168.100.199', '08:00:27:3F:C8:A1', 445,  'tcp',   '/share/passwords.txt', 'AKIAX9EXAMPLE2DEMO02', '2026-02-27T09:48:00Z'),
(5, '192.168.100.199', '08:00:27:3F:C8:A1', 5001, 'https', '/cgi-bin/authLogin.cgi', NULL,           '2026-02-27T09:38:00Z'),
-- Guest device (43) hitting decoys
(2, '192.168.100.168', 'B4:2E:99:51:F3:DC', 8081, 'http',  '/hub/advanced', NULL,                   '2026-02-23T19:15:00Z'),
(2, '192.168.100.168', 'B4:2E:99:51:F3:DC', 8081, 'http',  '/hub/appsList', NULL,                   '2026-02-23T19:18:00Z'),
(3, '192.168.100.168', 'B4:2E:99:51:F3:DC', 445,  'tcp',   '/share/',     NULL,                     '2026-02-23T19:22:00Z'),
-- Random mimic hits
(4, '192.168.100.199', '08:00:27:3F:C8:A1', 80,   'http',  '/',           NULL,                     '2026-02-26T02:40:00Z'),
(4, '192.168.100.199', '08:00:27:3F:C8:A1', 80,   'http',  '/api/system', NULL,                     '2026-02-26T02:41:00Z'),
(7, '192.168.100.199', '08:00:27:3F:C8:A1', 80,   'http',  '/',           NULL,                     '2026-02-26T02:45:00Z'),
(11,'192.168.100.199', '08:00:27:3F:C8:A1', 32400,'http',  '/web/index.html', NULL,                 '2026-02-26T02:50:00Z'),
(6, '192.168.100.168', 'B4:2E:99:51:F3:DC', 8081, 'http',  '/',           NULL,                     '2026-02-23T19:20:00Z');


-- ============================================================
-- SERVICE PROFILES (Squirrel Scouts fingerprints)
-- ============================================================

INSERT INTO service_profiles (device_id, ip_address, port, protocol, service_name, http_status, http_headers, http_body_snippet, http_server_header, favicon_hash, tls_cn, tls_issuer, tls_not_after, protocol_version, scouted_at) VALUES
-- Router
(1,  '192.168.100.1',   80,    'tcp', 'HTTP',   200, '{"Server": "TP-Link/1.0", "Content-Type": "text/html"}', '<title>Omada Controller</title>', 'TP-Link/1.0', 'a1b2c3d4', NULL, NULL, NULL, NULL, '2026-02-18T11:00:00Z'),
(1,  '192.168.100.1',   443,   'tcp', 'HTTPS',  200, '{"Server": "TP-Link/1.0"}', NULL, 'TP-Link/1.0', NULL, 'omada-router.local', 'TP-Link CA', '2027-01-15T00:00:00Z', 'TLSv1.3', '2026-02-18T11:00:00Z'),
-- NAS
(5,  '192.168.100.10',  5001,  'tcp', 'ADM',    200, '{"Server": "Apache"}', '<title>Asustor ADM</title>', 'Apache', 'e5f6a7b8', 'asustor-nas.local', 'Asustor Systems', '2027-06-01T00:00:00Z', 'TLSv1.3', '2026-02-18T11:05:00Z'),
(5,  '192.168.100.10',  32400, 'tcp', 'Plex',   200, '{"Server": "Plex"}', NULL, 'Plex', NULL, NULL, NULL, NULL, NULL, '2026-02-18T11:05:00Z'),
(5,  '192.168.100.10',  445,   'tcp', 'SMB',    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'SMBv3', '2026-02-18T11:05:00Z'),
-- Hubitat Hub
(9,  '192.168.100.23',  8081,  'tcp', 'HTTP',   200, '{"Server": "Hubitat/2.4.1"}', '<title>Hubitat Elevation</title>', 'Hubitat/2.4.1', 'c9d0e1f2', NULL, NULL, NULL, NULL, '2026-02-18T11:10:00Z'),
-- Printer
(33, '192.168.100.80',  80,    'tcp', 'HTTP',   200, '{"Server": "HP HTTP Server"}', '<title>HP LaserJet Pro M404n</title>', 'HP HTTP Server', '12345678', NULL, NULL, NULL, NULL, '2026-02-18T11:15:00Z'),
(33, '192.168.100.80',  9100,  'tcp', 'RAW',    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2026-02-18T11:15:00Z'),
-- LG TV
(15, '192.168.100.40',  8001,  'tcp', 'HTTP',   200, '{"Server": "LG Smart TV"}', NULL, 'LG Smart TV', NULL, NULL, NULL, NULL, NULL, '2026-02-18T11:20:00Z'),
-- PS5
(35, '192.168.100.90',  987,   'tcp', 'TCP',    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2026-02-18T11:25:00Z'),
-- Ring
(29, '192.168.100.70',  443,   'tcp', 'HTTPS',  200, NULL, NULL, NULL, NULL, 'eufy-doorbell.local', 'Anker Root CA', '2027-03-01T00:00:00Z', 'TLSv1.3', '2026-02-18T11:30:00Z'),
-- Suspicious VM
(42, '192.168.100.199', 80,    'tcp', 'HTTP',   200, '{"Server": "Apache/2.4.41 (Ubuntu)"}', '<title>Apache2 Ubuntu Default Page</title>', 'Apache/2.4.41 (Ubuntu)', NULL, NULL, NULL, NULL, NULL, '2026-02-26T02:35:00Z'),
(42, '192.168.100.199', 8080,  'tcp', 'HTTP',   200, '{"Server": "Werkzeug/2.3.7 Python/3.10.12"}', '<title>Debug Console</title>', 'Werkzeug/2.3.7 Python/3.10.12', NULL, NULL, NULL, NULL, NULL, '2026-02-26T02:35:00Z');


-- ============================================================
-- MIMIC TEMPLATES
-- ============================================================

INSERT INTO mimic_templates (source_device_id, source_ip, device_category, routes_json, server_header, credential_types_json, mdns_service_type, mdns_name, created_at, updated_at) VALUES
(1,  '192.168.100.1',  'router',       '[{"path": "/", "status": 200, "headers": {"Server": "TP-Link/1.0"}}]', 'TP-Link/1.0', '["generic_password"]', '_http._tcp', 'Omada-Router', '2026-02-18T12:00:00Z', '2026-02-18T12:00:00Z'),
(5,  '192.168.100.10', 'nas',          '[{"path": "/cgi-bin/authLogin.cgi", "status": 200, "headers": {"Server": "Apache"}}]', 'Apache', '["generic_password", "aws_key"]', '_https._tcp', 'Asustor-NAS', '2026-02-18T12:05:00Z', '2026-02-18T12:05:00Z'),
(9,  '192.168.100.23', 'smart_home',   '[{"path": "/hub/advanced/editPage", "status": 200, "headers": {"Server": "Hubitat/2.4.1"}}]', 'Hubitat/2.4.1', '["ha_token"]', '_hubitat._tcp', 'Hubitat-Elevation', '2026-02-18T12:10:00Z', '2026-02-18T12:10:00Z'),
(33, '192.168.100.80', 'printer',      '[{"path": "/", "status": 200, "headers": {"Server": "HP HTTP Server"}}]', 'HP HTTP Server', NULL, '_ipp._tcp', 'HP-LaserJet', '2026-02-18T12:15:00Z', '2026-02-18T12:15:00Z'),
(15, '192.168.100.40', 'smart_tv',     '[{"path": "/", "status": 200, "headers": {"Server": "LG Smart TV"}}]', 'LG Smart TV', NULL, '_lgtv._tcp', 'LG-OLED-TV', '2026-02-18T12:20:00Z', '2026-02-18T12:20:00Z'),
(29, '192.168.100.70', 'camera',       '[{"path": "/", "status": 200}]', NULL, NULL, '_eufy._tcp', 'Eufy-Doorbell', '2026-02-18T12:25:00Z', '2026-02-18T12:25:00Z'),
(25, '192.168.100.61', 'thermostat',   '[{"path": "/", "status": 200}]', NULL, NULL, '_nest._tcp', 'Nest-Thermostat', '2026-02-18T12:30:00Z', '2026-02-18T12:30:00Z'),
(5,  '192.168.100.10', 'nas',          '[{"path": "/web/index.html", "status": 200, "headers": {"Server": "Plex"}}]', 'Plex', NULL, '_plex._tcp', 'Plex-Media-Server', '2026-02-18T12:35:00Z', '2026-02-18T12:35:00Z'),
(35, '192.168.100.90', 'gaming_console','[{"path": "/", "status": 200}]', NULL, NULL, NULL, 'PS5-Remote', '2026-02-18T12:40:00Z', '2026-02-18T12:40:00Z'),
(6,  '192.168.100.20', 'computer',     '[{"path": "/", "status": 200}]', NULL, NULL, '_airplay._tcp', 'MacBook-Pro', '2026-02-18T12:45:00Z', '2026-02-18T12:45:00Z');


-- ============================================================
-- DEVICE FINGERPRINTS (selected devices)
-- ============================================================

INSERT INTO device_fingerprints (device_id, mac_address, mdns_hostname, signal_count, confidence, first_seen, last_seen) VALUES
(1,  'FC:EC:DA:A1:37:02', 'omada-router.local',       4, 0.98, '2026-01-15T08:00:00Z', '2026-02-27T11:30:00Z'),
(5,  '00:11:32:AB:CD:EF', 'asustor-nas.local',           5, 0.99, '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
(6,  '3C:22:FB:19:A7:D5', 'Alexs-MacBook-Pro.local',  4, 0.97, '2026-01-15T09:00:00Z', '2026-02-27T11:28:00Z'),
(9,  'DC:A6:32:7F:14:C3', 'hubitat.local',             4, 0.96, '2026-01-16T11:00:00Z', '2026-02-27T11:30:00Z'),
(15, '8C:AA:B5:71:FE:33', 'LG-OLED-TV.local',          3, 0.92, '2026-01-17T15:00:00Z', '2026-02-27T03:00:00Z'),
(19, '94:9F:3E:D7:22:A1', 'Living-Room.local',        3, 0.95, '2026-01-17T16:00:00Z', '2026-02-27T11:30:00Z'),
(29, '4C:B9:EA:55:A3:D1', 'eufy-doorbell.local',       3, 0.91, '2026-01-16T14:00:00Z', '2026-02-27T11:30:00Z'),
(33, '3C:D9:2B:F4:11:63', 'HP-LaserJet.local',        4, 0.94, '2026-01-17T08:00:00Z', '2026-02-27T09:15:00Z'),
(42, '08:00:27:3F:C8:A1', NULL,                        2, 0.45, '2026-02-26T02:33:00Z', '2026-02-26T04:17:00Z');


-- ============================================================
-- CONNECTION BASELINES (learned behavior)
-- ============================================================

INSERT INTO connection_baselines (device_id, dest_ip, dest_port, hit_count, first_seen, last_seen) VALUES
-- Router → WAN
(1,  '1.1.1.1',        443, 1200, '2026-01-15T08:00:00Z', '2026-02-27T11:30:00Z'),
(1,  '8.8.8.8',        53,  800,  '2026-01-15T08:00:00Z', '2026-02-27T11:30:00Z'),
-- MacBook → common destinations
(6,  '140.82.121.4',   443, 350,  '2026-01-15T09:00:00Z', '2026-02-27T11:28:00Z'),
(6,  '17.253.144.10',  443, 600,  '2026-01-15T09:00:00Z', '2026-02-27T11:28:00Z'),
-- NAS → cloud backup
(5,  '52.216.50.15',   443, 450,  '2026-01-16T10:00:00Z', '2026-02-27T11:30:00Z'),
-- Echo → Amazon
(23, '54.239.28.85',   443, 1500, '2026-01-19T10:00:00Z', '2026-02-27T11:30:00Z'),
-- Robot vacuum → Roborock cloud
(28, '34.237.65.113',  443, 200,  '2026-01-22T11:00:00Z', '2026-02-27T08:30:00Z');


-- PAIRING: preserved from real database (not overwritten by seed script)


-- ============================================================
-- SCHEMA VERSION (keep current)
-- ============================================================

INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (6, '2026-01-15T08:00:00Z');


-- ============================================================
-- VERIFY
-- ============================================================

SELECT '--- Marketing Data Summary ---';
SELECT 'Devices: ' || COUNT(*) FROM devices;
SELECT 'Online: ' || SUM(is_online) || '  Offline: ' || SUM(1 - is_online) FROM devices;
SELECT 'Trust — Approved: ' || SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) || '  Rejected: ' || SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) || '  Unreviewed: ' || SUM(CASE WHEN status='unknown' THEN 1 ELSE 0 END) FROM device_trust;
SELECT 'Alerts: ' || COUNT(*) || '  (Unread: ' || SUM(CASE WHEN read_at IS NULL THEN 1 ELSE 0 END) || ')' FROM home_alerts;
SELECT 'Alert types: ' || GROUP_CONCAT(DISTINCT alert_type) FROM home_alerts;
SELECT 'Incidents: ' || COUNT(*) || '  (Active: ' || SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) || ')' FROM incidents;
SELECT 'Decoys: ' || COUNT(*) || '  Connections: ' || SUM(connection_count) || '  Trips: ' || SUM(credential_trip_count) FROM decoys;
SELECT 'Planted credentials: ' || COUNT(*) || '  (Tripped: ' || SUM(tripped) || ')' FROM planted_credentials;
SELECT 'Service profiles: ' || COUNT(*) FROM service_profiles;
SELECT 'Mimic templates: ' || COUNT(*) FROM mimic_templates;
SELECT 'Virtual IPs: ' || COUNT(*) FROM virtual_ips;
SELECT 'Open ports: ' || COUNT(*) FROM device_open_ports;
SELECT 'Fingerprints: ' || COUNT(*) FROM device_fingerprints;
SELECT 'Baselines: ' || COUNT(*) FROM connection_baselines;
