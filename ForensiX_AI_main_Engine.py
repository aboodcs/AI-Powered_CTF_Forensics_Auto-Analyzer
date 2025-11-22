"""
ForensiX AI - Intelligent CTF Forensics Analyzer
Main Engine Module
"""

import os
import magic
import hashlib
import numpy as np
from pathlib import Path
from datetime import datetime
import json

class ForensiXEngine:
    """المحرك الرئيسي لتحليل الملفات"""
    
    def __init__(self):
        self.results = {}
        self.suspicious_score = 0
        
    def analyze_file(self, file_path):
        """تحليل شامل للملف"""
        print(f"\n🔍 Analyzing: {file_path}")
        print("="*60)
        
        if not os.path.exists(file_path):
            return {"error": "File not found"}
        
        # معلومات أساسية
        self.results['file_info'] = self._get_file_info(file_path)
        
        # تحديد نوع الملف
        file_type = self.results['file_info']['mime_type']
        
        # تحليل حسب النوع
        if 'image' in file_type:
            self.results['image_analysis'] = self._analyze_image(file_path)
        elif 'text' in file_type or file_type == 'application/octet-stream':
            self.results['text_analysis'] = self._analyze_text(file_path)
        elif 'pcap' in file_type or file_path.endswith('.pcap'):
            self.results['network_analysis'] = self._analyze_pcap(file_path)
        
        # تحليل عام لكل الملفات
        self.results['entropy_analysis'] = self._analyze_entropy(file_path)
        self.results['strings_analysis'] = self._extract_strings(file_path)
        self.results['suspicious_score'] = self.suspicious_score
        
        # إنشاء التقرير
        self._generate_report()
        
        return self.results
    
    def _get_file_info(self, file_path):
        """استخراج معلومات الملف الأساسية"""
        stat = os.stat(file_path)
        
        # حساب الهاش
        with open(file_path, 'rb') as f:
            file_data = f.read()
            md5 = hashlib.md5(file_data).hexdigest()
            sha256 = hashlib.sha256(file_data).hexdigest()
        
        # تحديد نوع الملف
        try:
            mime = magic.from_file(file_path, mime=True)
        except:
            mime = "unknown"
        
        return {
            'filename': os.path.basename(file_path),
            'size': stat.st_size,
            'mime_type': mime,
            'md5': md5,
            'sha256': sha256,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
        }
    
    def _analyze_entropy(self, file_path):
        """تحليل الإنتروبيا - مؤشر على التشفير/الضغط"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if len(data) == 0:
            return {'entropy': 0, 'verdict': 'Empty file'}
        
        # حساب الإنتروبيا
        entropy = 0
        for i in range(256):
            freq = data.count(bytes([i])) / len(data)
            if freq > 0:
                entropy -= freq * np.log2(freq)
        
        # التقييم
        verdict = "Normal"
        if entropy > 7.5:
            verdict = "⚠️ High entropy - possibly encrypted/compressed"
            self.suspicious_score += 30
        elif entropy > 7.0:
            verdict = "⚠️ Medium-high entropy - check for encoding"
            self.suspicious_score += 15
        
        return {
            'entropy': round(entropy, 3),
            'verdict': verdict,
            'max_entropy': 8.0
        }
    
    def _extract_strings(self, file_path, min_length=6):
        """استخراج النصوص المفيدة من الملف"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # استخراج ASCII strings
        strings = []
        current = b''
        
        for byte in data:
            if 32 <= byte <= 126:  # printable ASCII
                current += bytes([byte])
            else:
                if len(current) >= min_length:
                    strings.append(current.decode('ascii'))
                current = b''
        
        # تحليل الـstrings
        flags = self._find_flags(strings)
        base64_strings = [s for s in strings if self._is_base64(s)]
        urls = [s for s in strings if 'http' in s.lower() or 'www.' in s.lower()]
        
        result = {
            'total_strings': len(strings),
            'sample_strings': strings[:20],
            'potential_flags': flags,
            'base64_candidates': base64_strings[:10],
            'urls': urls
        }
        
        if flags:
            self.suspicious_score += 50
        if base64_strings:
            self.suspicious_score += 20
        
        return result
    
    def _find_flags(self, strings):
        """البحث عن أعلام CTF محتملة"""
        flags = []
        patterns = [
            'flag{', 'FLAG{', 'ctf{', 'CTF{',
            'flag:', 'FLAG:', 'picoCTF{', 'HTB{'
        ]
        
        for s in strings:
            for pattern in patterns:
                if pattern in s:
                    flags.append(s)
                    break
        
        return flags
    
    def _is_base64(self, s):
        """فحص إذا كان النص base64"""
        if len(s) < 20 or len(s) % 4 != 0:
            return False
        
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        return all(c in base64_chars for c in s)
    
    def _analyze_image(self, file_path):
        """تحليل الصور - كشف الستيجانوغرافي"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            img = Image.open(file_path)
            
            # استخراج EXIF
            exif_data = {}
            try:
                exif = img._getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_data[tag] = str(value)
            except:
                pass
            
            # تحليل LSB (بسيط)
            pixels = list(img.getdata())
            lsb_analysis = self._analyze_lsb(pixels)
            
            result = {
                'dimensions': f"{img.width}x{img.height}",
                'mode': img.mode,
                'format': img.format,
                'exif_data': exif_data,
                'lsb_analysis': lsb_analysis
            }
            
            if lsb_analysis['suspicious']:
                self.suspicious_score += 40
            
            return result
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_lsb(self, pixels):
        """تحليل بسيط للـLSB"""
        if not pixels:
            return {'suspicious': False}
        
        # حساب توزيع LSB
        lsb_bits = []
        for pixel in pixels[:1000]:  # عينة
            if isinstance(pixel, tuple):
                for channel in pixel:
                    lsb_bits.append(channel & 1)
            else:
                lsb_bits.append(pixel & 1)
        
        # التوزيع الطبيعي يجب أن يكون ~50/50
        ones = sum(lsb_bits)
        ratio = ones / len(lsb_bits) if lsb_bits else 0.5
        
        suspicious = abs(ratio - 0.5) > 0.15
        
        return {
            'suspicious': suspicious,
            'lsb_ratio': round(ratio, 3),
            'verdict': '⚠️ Unusual LSB distribution - possible steganography' if suspicious else 'Normal LSB distribution'
        }
    
    def _analyze_text(self, file_path):
        """تحليل الملفات النصية"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # تحليل اللغة والأنماط
            lines = content.split('\n')
            
            # البحث عن تشفيرات شائعة
            encodings_found = []
            if 'base64' in content.lower():
                encodings_found.append('base64 reference')
            
            # ROT patterns
            if any(c.isupper() for c in content) and any(c.islower() for c in content):
                encodings_found.append('mixed case - possible cipher')
            
            result = {
                'line_count': len(lines),
                'char_count': len(content),
                'encodings_detected': encodings_found,
                'sample': content[:500]
            }
            
            return result
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_pcap(self, file_path):
        """تحليل ملفات الشبكة"""
        try:
            from scapy.all import rdpcap, IP, TCP, UDP
            
            packets = rdpcap(file_path)
            
            # تحليل بسيط
            ips = set()
            protocols = {}
            
            for pkt in packets:
                if IP in pkt:
                    ips.add(pkt[IP].src)
                    ips.add(pkt[IP].dst)
                
                protocol = pkt.sprintf("%IP.proto%")
                protocols[protocol] = protocols.get(protocol, 0) + 1
            
            result = {
                'total_packets': len(packets),
                'unique_ips': len(ips),
                'protocols': protocols,
                'sample_ips': list(ips)[:10]
            }
            
            # الشبهة: عدد كبير من الاتصالات لـIP واحد
            if len(ips) < 5 and len(packets) > 100:
                result['verdict'] = '⚠️ Suspicious: Many packets to few IPs'
                self.suspicious_score += 25
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'note': 'Install scapy: pip install scapy'}
    
    def _generate_report(self):
        """إنشاء تقرير نهائي"""
        print("\n" + "="*60)
        print("📊 FORENSIX AI - ANALYSIS REPORT")
        print("="*60)
        
        # معلومات الملف
        info = self.results.get('file_info', {})
        print(f"\n📁 File: {info.get('filename', 'N/A')}")
        print(f"   Size: {info.get('size', 0)} bytes")
        print(f"   Type: {info.get('mime_type', 'unknown')}")
        print(f"   MD5: {info.get('md5', 'N/A')}")
        
        # الإنتروبيا
        entropy = self.results.get('entropy_analysis', {})
        print(f"\n🔬 Entropy: {entropy.get('entropy', 0)}/8.0")
        print(f"   {entropy.get('verdict', '')}")
        
        # النتائج المهمة
        strings = self.results.get('strings_analysis', {})
        if strings.get('potential_flags'):
            print(f"\n🚩 POTENTIAL FLAGS FOUND:")
            for flag in strings['potential_flags']:
                print(f"   → {flag}")
        
        if strings.get('base64_candidates'):
            print(f"\n🔐 Base64 candidates: {len(strings['base64_candidates'])}")
        
        # الدرجة النهائية
        print(f"\n⚠️  SUSPICIOUS SCORE: {self.suspicious_score}/100")
        
        if self.suspicious_score > 70:
            print("   🔴 HIGH - Definitely investigate!")
        elif self.suspicious_score > 40:
            print("   🟡 MEDIUM - Worth checking")
        else:
            print("   🟢 LOW - Probably clean")
        
        print("\n" + "="*60)


# CLI Interface
if __name__ == "__main__":
    import sys
    
    print("""
    ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗
    ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║╚██╗██╔╝
    █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║ ╚███╔╝ 
    ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║ ██╔██╗ 
    ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██╔╝ ██╗
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝
    
    🤖 AI-Powered CTF Forensics Analyzer
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python forensix.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    engine = ForensiXEngine()
    results = engine.analyze_file(file_path)
    
    # حفظ التقرير باسم قوي جداً
    filename = os.path.basename(file_path).split('.')[0]  # اسم الملف بدون الامتداد
    timestamp = datetime.now().strftime('%d%b%y_%H%M').upper()  # 22NOV24_1530
    threat_level = "CRITICAL" if engine.suspicious_score > 70 else "HIGH" if engine.suspicious_score > 40 else "MEDIUM"
    
    output_file = f"FORENSIX_BLACKBOX_{filename}_{threat_level}_{timestamp}.json"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n💀 THREAT INTELLIGENCE EXTRACTED → {output_file}")