import os
import base64
from PIL import Image
import random

class ForensiXTester:
    def __init__(self):
        self.test_dir = "test_samples"
        os.makedirs(self.test_dir, exist_ok=True)

    def create_all_samples(self):
        print("🧪 Creating test samples...")
        self.create_flag_text()
        self.create_base64_file()
        self.create_high_entropy_file()
        self.create_stego_image()
        self.create_normal_image()
        print(f"✅ All samples created in '{self.test_dir}/' directory")
        print("\nTest with:")
        print(f"  python forensix.py {self.test_dir}/flag_file.txt")
        print(f"  python forensix.py {self.test_dir}/stego_image.png")

    def create_flag_text(self):
        content = """
This is a sample CTF challenge file.
Some random text here to make it look normal.

Lorem ipsum dolor sit amet, consectetur adipiscing elit.

But wait… there’s something hidden here:
flag{th1s_1s_4_t3st_fl4g_2024}

More text to confuse the analyzer…
The quick brown fox jumps over the lazy dog.
"""
        path = os.path.join(self.test_dir, "flag_file.txt")
        with open(path, 'w') as f:
            f.write(content)
        print(f"  ✓ Created: flag_file.txt")

    def create_base64_file(self):
        secret = "flag{bas364_3nc0d3d_s3cr3t}"
        encoded = base64.b64encode(secret.encode()).decode()
        content = f"""
Some configuration file…
API_KEY=1234567890abcdef
SECRET={encoded}
DEBUG=true
"""
        path = os.path.join(self.test_dir, "config.txt")
        with open(path, 'w') as f:
            f.write(content)
        print(f"  ✓ Created: config.txt (contains base64)")

    def create_high_entropy_file(self):
        random_data = bytes([random.randint(0, 255) for _ in range(1024)])
        path = os.path.join(self.test_dir, "encrypted.bin")
        with open(path, 'wb') as f:
            f.write(random_data)
        print(f"  ✓ Created: encrypted.bin (high entropy)")

    def create_stego_image(self):
        img = Image.new('RGB', (100, 100), color='white')
        pixels = img.load()
        message = "SECRET"
        binary_message = ''.join(format(ord(c), '08b') for c in message)
        idx = 0
        for i in range(100):
            for j in range(100):
                if idx < len(binary_message):
                    r, g, b = pixels[i, j]
                    r = (r & 0xFE) | int(binary_message[idx])
                    pixels[i, j] = (r, g, b)
                    idx += 1
        path = os.path.join(self.test_dir, "stego_image.png")
        img.save(path)
        print(f"  ✓ Created: stego_image.png (LSB steganography)")

    def create_normal_image(self):
        img = Image.new('RGB', (100, 100))
        pixels = img.load()
        for i in range(100):
            for j in range(100):
                pixels[i, j] = (i*2, j*2, 128)
        path = os.path.join(self.test_dir, "normal_image.png")
        img.save(path)
        print(f"  ✓ Created: normal_image.png (normal image)")

    def create_test_pcap(self):
        try:
            from scapy.all import IP, TCP, wrpcap
            packets = []
            for i in range(100):
                pkt = IP(dst="192.168.1.1")/TCP(dport=80)
                packets.append(pkt)
            path = os.path.join(self.test_dir, "sample.pcap")
            wrpcap(path, packets)
            print(f"  ✓ Created: sample.pcap")
        except ImportError:
            print("  ⚠ Skipped: sample.pcap (install scapy)")

class BenchmarkTest:
    def __init__(self):
        self.results = {}

    def run_benchmark(self):
        print("\n🏃 Running benchmark tests...")
        from forensix import ForensiXEngine
        import time
        engine = ForensiXEngine()
        tester = ForensiXTester()
        tester.create_all_samples()
        test_files = [
            "flag_file.txt",
            "config.txt",
            "encrypted.bin",
            "stego_image.png",
            "normal_image.png"
        ]
        for filename in test_files:
            path = os.path.join(tester.test_dir, filename)
            if os.path.exists(path):
                start = time.time()
                try:
                    engine.analyze_file(path)
                    elapsed = time.time() - start
                    self.results[filename] = {'status': 'success', 'time': round(elapsed, 3)}
                except Exception as e:
                    self.results[filename] = {'status': 'failed', 'error': str(e)}
        self._print_results()

    def _print_results(self):
        print("\n" + "="*60)
        print("📊 BENCHMARK RESULTS")
        print("="*60)
        total_time = 0
        success_count = 0
        for filename, result in self.results.items():
            status = "✅" if result['status'] == 'success' else "❌"
            print(f"{status} {filename:30} ", end="")
            if result['status'] == 'success':
                print(f"{result['time']}s")
                total_time += result['time']
                success_count += 1
            else:
                print(f"Error: {result['error']}")
        print("="*60)
        print(f"Total: {success_count}/{len(self.results)} passed")
        print(f"Average time: {round(total_time/success_count, 3)}s" if success_count > 0 else "")
        print("="*60)

def run_unit_tests():
    print("\n🧪 Running unit tests…\n")
    from forensix import ForensiXEngine
    engine = ForensiXEngine()
    test_strings = [
        "flag{test123}",
        "FLAG{ANOTHER_ONE}",
        "picoCTF{hello_world}",
        "normal text"
    ]
    flags = engine._find_flags(test_strings)
    assert len(flags) == 3, "Flag detection failed"
    print("✅ Test 1: Flag detection passed")
    test_base64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0"
    assert engine._is_base64(test_base64), "Base64 detection failed"
    print("✅ Test 2: Base64 detection passed")
    test_data = b'\x00' * 100
    result = engine._analyze_entropy_data(test_data)
    assert result['entropy'] < 1.0, "Entropy calculation failed"
    print("✅ Test 3: Entropy calculation passed")
    print("\n✅ All unit tests passed!")

if __name__ == "__main__":
    import sys
    print("""
███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║╚██╗██╔╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║ ╚███╔╝ 
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║ ██╔██╗ 
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██╔╝ ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝

🧪 Testing Suite
""")
    if len(sys.argv) > 1 and sys.argv[1] == '--benchmark':
        bench = BenchmarkTest()
        bench.run_benchmark()
    elif len(sys.argv) > 1 and sys.argv[1] == '--unit':
        run_unit_tests()
    else:
        tester = ForensiXTester()
        tester.create_all_samples()
        print("\n📖 Usage:")
        print("  python test_forensix.py              # Create samples")
        print("  python test_forensix.py --benchmark  # Run benchmark")
        print("  python test_forensix.py --unit       # Run unit tests")
