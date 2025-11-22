import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import re

class MLAnalyzer:

    def __init__(self):
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)

    def analyze_file_features(self, file_path):
        features = {}
        with open(file_path, 'rb') as f:
            data = f.read()
        features['byte_distribution'] = self._calculate_byte_distribution(data)
        features['bigram_entropy'] = self._calculate_ngram_entropy(data, n=2)
        features['trigram_entropy'] = self._calculate_ngram_entropy(data, n=3)
        features['repetition_score'] = self._detect_repetition(data)
        features['chi_square'] = self._chi_square_test(data)
        return features

    def _calculate_byte_distribution(self, data):
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        return (counts / len(data)).tolist() if len(data) > 0 else [0]*256

    def _calculate_ngram_entropy(self, data, n=2):
        if len(data) < n:
            return 0.0
        ngrams = {}
        for i in range(len(data) - n + 1):
            ngram = data[i:i+n]
            ngrams[ngram] = ngrams.get(ngram, 0) + 1
        total = sum(ngrams.values())
        entropy = 0
        for count in ngrams.values():
            p = count / total
            entropy -= p * np.log2(p)
        return entropy

    def _detect_repetition(self, data, window_size=16):
        if len(data) < window_size * 2:
            return 0.0
        patterns = {}
        for i in range(len(data) - window_size + 1):
            pattern = data[i:i+window_size]
            patterns[pattern] = patterns.get(pattern, 0) + 1
        repeated = sum(1 for count in patterns.values() if count > 1)
        return repeated / len(patterns) if patterns else 0.0

    def _chi_square_test(self, data):
        if len(data) == 0:
            return 0.0
        observed = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        expected = len(data) / 256
        chi_square = np.sum((observed - expected) ** 2 / expected)
        return chi_square

    def detect_anomalies(self, file_paths):
        all_features = []
        for path in file_paths:
            try:
                features = self.analyze_file_features(path)
                feature_vector = [
                    features['bigram_entropy'],
                    features['trigram_entropy'],
                    features['repetition_score'],
                    features['chi_square'] / 10000
                ]
                all_features.append(feature_vector)
            except:
                all_features.append([0, 0, 0, 0])
        if not all_features:
            return []
        X = np.array(all_features)
        X_scaled = self.scaler.fit_transform(X)
        predictions = self.anomaly_detector.fit_predict(X_scaled)
        anomalies = [file_paths[i] for i, pred in enumerate(predictions) if pred == -1]
        return anomalies

class NLPFlagDetector:

    def __init__(self):
        self.flag_patterns = [
            r'flag\{[^\}]+\}',
            r'FLAG\{[^\}]+\}',
            r'ctf\{[^\}]+\}',
            r'CTF\{[^\}]+\}',
            r'picoCTF\{[^\}]+\}',
            r'HTB\{[^\}]+\}',
            r'\w+\{[a-zA-Z0-9_\-]+\}',
        ]
        self.encoding_patterns = {
            'base64': r'[A-Za-z0-9+/]{20,}={0,2}',
            'hex': r'(0x)?[0-9a-fA-F]{20,}',
            'base32': r'[A-Z2-7]{20,}={0,6}',
            'morse': r'[.\-\s]{20,}',
            'binary': r'[01]{20,}',
        }

    def find_flags(self, text):
        flags = []
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        return list(set(flags))

    def detect_encodings(self, text):
        detected = {}
        for encoding, pattern in self.encoding_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                detected[encoding] = matches[:5]
        return detected

    def analyze_text_intelligence(self, text):
        results = {
            'flags': self.find_flags(text),
            'encodings': self.detect_encodings(text),
            'statistics': {
                'length': len(text),
                'words': len(text.split()),
                'lines': len(text.split('\n')),
                'uppercase_ratio': sum(1 for c in text if c.isupper()) / len(text) if text else 0,
                'digit_ratio': sum(1 for c in text if c.isdigit()) / len(text) if text else 0,
            }
        }
        if results['statistics']['uppercase_ratio'] > 0.8:
            results['possible_cipher'] = 'ROT13 or Caesar cipher'
        if results['statistics']['digit_ratio'] > 0.7:
            results['possible_encoding'] = 'Numeric encoding or coordinates'
        return results

class StegoMLDetector:

    def __init__(self):
        pass

    def analyze_image_advanced(self, image_path):
        try:
            from PIL import Image
            img = Image.open(image_path)
            results = {}
            results['lsb_planes'] = self._analyze_bit_planes(img)
            results['chi_square_test'] = self._chi_square_stego_test(img)
            results['histogram_anomaly'] = self._analyze_histogram(img)
            return results
        except Exception as e:
            return {'error': str(e)}

    def _analyze_bit_planes(self, img):
        pixels = list(img.getdata())
        bit_planes = {i: [] for i in range(8)}
        for pixel in pixels[:1000]:
            if isinstance(pixel, tuple):
                val = pixel[0]
            else:
                val = pixel
            for bit in range(8):
                bit_planes[bit].append((val >> bit) & 1)
        entropies = {}
        for bit, values in bit_planes.items():
            ones = sum(values)
            ratio = ones / len(values) if values else 0.5
            entropies[f'bit_{bit}'] = ratio
        lsb_suspicious = abs(entropies['bit_0'] - 0.5) < 0.05
        return {
            'entropies': entropies,
            'lsb_suspicious': lsb_suspicious,
            'verdict': '⚠️ Possible LSB steganography' if lsb_suspicious else 'Normal'
        }

    def _chi_square_stego_test(self, img):
        pixels = list(img.getdata())
        even_count = {}
        odd_count = {}
        for pixel in pixels[:5000]:
            if isinstance(pixel, tuple):
                val = pixel[0]
            else:
                val = pixel
            if val % 2 == 0:
                even_count[val] = even_count.get(val, 0) + 1
            else:
                odd_count[val] = odd_count.get(val, 0) + 1
        chi_square = 0
        for val in range(0, 256, 2):
            even = even_count.get(val, 0)
            odd = odd_count.get(val + 1, 0)
            expected = (even + odd) / 2
            if expected > 0:
                chi_square += ((even - expected) ** 2 / expected)
        suspicious = chi_square < 100
        return {
            'chi_square': chi_square,
            'suspicious': suspicious,
            'verdict': '⚠️ Chi-square test suggests steganography' if suspicious else 'Normal distribution'
        }

    def _analyze_histogram(self, img):
        pixels = list(img.getdata())
        histogram = {}
        for pixel in pixels:
            if isinstance(pixel, tuple):
                val = pixel[0]
            else:
                val = pixel
            histogram[val] = histogram.get(val, 0) + 1
        values = list(histogram.values())
        if values:
            mean = np.mean(values)
            std = np.std(values)
            unusual = std > mean * 2
            return {
                'mean': mean,
                'std': std,
                'unusual_distribution': unusual
            }
        return {'unusual_distribution': False}

if __name__ == "__main__":
    print("🤖 ForensiX ML Analyzer Module")
    print("This module provides advanced ML-based analysis")
    print("\nFeatures:")
    print("  • Anomaly Detection using Isolation Forest")
    print("  • NLP-based Flag Detection")
    print("  • Advanced Steganography Detection")
    print("\nImport this module in forensix.py for enhanced analysis!")
