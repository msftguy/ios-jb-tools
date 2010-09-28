using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Globalization;

namespace dif_patcher {
    class Program {
        static void Main(string[] args) {
            if (args.Length < 3) {
                Console.WriteLine("Usage: {0} <dif file> <source file> <dest file>", Process.GetCurrentProcess().ProcessName);
            } else {
                apply_dif(args[0], args[1], args[2]);
            }
        }

        private static void apply_dif(string difFile, string source, string dest) {
            byte[] sourceBytes = File.ReadAllBytes(source);
            string[] difLines = File.ReadAllLines(difFile);
            bool mismatch = false;
            foreach (string l in difLines) {
                Match m = Regex.Match(l, @"(?<offset>[a-f\d]+): (?<from>[a-f\d]+) (?<to>[a-f\d]+)", RegexOptions.IgnoreCase);
                if (m.Success) {
                    uint offset = UInt32.Parse(m.Groups["offset"].Value, NumberStyles.HexNumber);
                    uint fromByte = UInt32.Parse(m.Groups["from"].Value, NumberStyles.HexNumber);
                    Debug.Assert(fromByte < 0x100);
                    uint toByte = UInt32.Parse(m.Groups["to"].Value, NumberStyles.HexNumber);
                    Debug.Assert(toByte < 0x100);
                    if (sourceBytes[offset] != (byte)fromByte) {
                        Console.WriteLine("Mismatch at 0x{0:X8}: need {1:X2}, got {2:X2}", offset, (byte)fromByte, sourceBytes[offset]);
                        mismatch = true;
                    } else {
                        sourceBytes[offset] = (byte)toByte;
                    }
                }
            }
            if (!mismatch) {
                File.WriteAllBytes(dest, sourceBytes);
            } else {
                Console.WriteLine("Source file mismatches detected; nothing done!");            
            }
        }
    }
}
