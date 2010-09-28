using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Diagnostics;
using System.Xml.Serialization;
using System.Collections;

namespace ConsoleApplication1 {
    static public class Useful {
        public static string BytesAsString(byte[] bytes) {
            StringBuilder result = new StringBuilder();
            foreach (byte b in bytes) {
                if (result.Length != 0) {
                    result.Append(" ");
                }
                result.AppendFormat("{0:X2}", b);
            }
            return result.ToString();
        }
        public static string MatchDetails(Patch p) {
            StringBuilder result = new StringBuilder();
            byte[] beforeBytes = new byte[p.patchOffset];
            byte[] origBytes = new byte[p.patchBytes.Length];
            byte[] afterBytes = new byte[p.matchBytes.Length - p.patchBytes.Length - p.patchOffset];
            Array.ConstrainedCopy(p.matchBytes, 0, beforeBytes, 0, beforeBytes.Length);
            Array.ConstrainedCopy(p.matchBytes, p.patchOffset, origBytes, 0, origBytes.Length);
            Array.ConstrainedCopy(p.matchBytes, p.patchOffset + p.patchBytes.Length, afterBytes, 0, afterBytes.Length);
            result.AppendFormat("{0}{{{1}}}{2}", BytesAsString(beforeBytes), BytesAsString(origBytes), BytesAsString(afterBytes));
            return result.ToString();
        }
        public static string PatchDetails(Patch p) {
            StringBuilder result = new StringBuilder();
            result.AppendFormat("[{0}] => [{1}]", MatchDetails(p), BytesAsString(p.patchBytes));
            return result.ToString();
        }
    }
        
    [Serializable]
    public class Patch {
        public const int MinMatchSize = 0x10;
        public const int MaxPatchSize = 0x100;
        public byte[] matchBytes;
        public byte[] patchBytes;
        public int patchOffset;
        public double quality;

        public static int MatchAreaSize(int patchSize) {
            return Math.Max(Patch.MinMatchSize, patchSize * 2);
        }

        public Patch() { }

        public Patch(byte[] orig, byte[] mod, int patchOffset, int entropyQuality) {
            matchBytes = orig;
            patchBytes = mod;
            this.patchOffset = patchOffset;
            this.quality = ((double)entropyQuality) / matchBytes.Length;
        }
    }
    
    class Program {
      
        static Patch processChunk(byte[] orig, byte[] mod, int chunkStart, int chunkEnd) {
            int patchSize = chunkEnd - chunkStart;
            Debug.Assert(patchSize < Patch.MaxPatchSize);
            int matchAreaSize = Patch.MatchAreaSize(patchSize);
            int matchBefore = (matchAreaSize - patchSize) / 2;
            int matchAfter = matchAreaSize - (patchSize + matchBefore);
            Debug.Assert(matchBefore <= chunkStart);
            Debug.Assert(chunkEnd + matchAfter <= orig.Length);

            byte[] origBytes = new byte[matchAreaSize];
            byte[] patchBytes = new byte[patchSize];
            Array.ConstrainedCopy(orig, chunkStart - matchBefore, origBytes, 0, matchAreaSize);
            Array.ConstrainedCopy(mod, chunkStart, patchBytes, 0, patchSize);
            MemoryStream ms = new MemoryStream();
            DeflateStream comp = new DeflateStream(ms, CompressionMode.Compress);
            comp.WriteByte(0);
            comp.Flush();
            long base_len = ms.Length;
            comp.Write(origBytes, 0, origBytes.Length);
            comp.Flush();
            return new Patch(origBytes, patchBytes, matchBefore, Convert.ToInt32(ms.Length - base_len));
        }

        static void diffFiles(string origPath, string modPath, string diffFile) {
            byte[] orig = File.ReadAllBytes(origPath);
            byte[] mod = File.ReadAllBytes(modPath);
            int commonSize = Math.Min(orig.Length, mod.Length);
            int chunkStart = -1;
            int chunkEnd = -1;
            bool inChunk = false;
            bool previouslyInChunk = false;
            List<Patch> patches = new List<Patch>();
            for (int i = 0; i < commonSize; ++i) {
                inChunk = orig[i] != mod[i];
                if (previouslyInChunk != inChunk) {
                    previouslyInChunk = inChunk;
                    if (inChunk) {
                        chunkStart = i;
                    } else {
                        chunkEnd = i;
                        patches.Add(processChunk(orig, mod, chunkStart, chunkEnd));
                    }
                }
            }
            Debug.Assert(!inChunk);
            Console.WriteLine("{0} patches located", patches.Count);
            foreach (Patch p in patches) {

                Console.WriteLine("{0} bytes, {1:P0} quality:\t{2}", p.matchBytes.Length, p.quality, Useful.MatchDetails(p));
            }
            using(StreamWriter sw = new StreamWriter(diffFile)) {
                XmlSerializer xs = new XmlSerializer(typeof(List<Patch>));
                xs.Serialize(sw, patches);
                sw.Flush();
            }
        }

        static void patchFile(string origPath, string patchedPath, string diffFile) {
            List<Patch> patches;
            using (StreamReader sr = new StreamReader(diffFile)) {
                XmlSerializer xs = new XmlSerializer(typeof(List<Patch>));
                patches = (List<Patch>) xs.Deserialize(sr);
            }

            byte[] orig = File.ReadAllBytes(origPath);
            byte[] mod = new byte[orig.Length];
            Array.Copy(orig, mod, orig.Length);
            int cApplied = 0, cTodo = 0;
            
            int patchNum = 0;
            
            foreach (Patch p in patches) {
                Console.WriteLine();
                patchNum++;
                int manualLoc = 0;
                if (g_overrides.ContainsKey(patchNum)) {
                    manualLoc = g_overrides[patchNum];
                }
                List<int> matchLoc = new List<int>();
                byte[] match = p.matchBytes;
                for (int i = 0; i < orig.Length - match.Length; ++i) {
                    bool mismatch = false;
                    for (int j = 0; j < match.Length; ++j) {
                        if (orig[i + j] != match[j]) {
                            mismatch = true;
                            break;
                        }
                    }
                    if (mismatch) 
                        continue;
                    matchLoc.Add(i);
                }

                int applyAtOffset = -1;

                int cMatches = matchLoc.Count;
                if (cMatches == 1) {
                    applyAtOffset = matchLoc[0] + p.patchOffset;                
                    Console.WriteLine("<<<{0}>>> 100% MATCH: {1} bytes at 0x{2:X8}\n{3}", patchNum, p.patchBytes.Length, matchLoc[0] + p.patchOffset, 
                        Useful.PatchDetails(p));
                } else if (cMatches > 1) {
                    Console.WriteLine("<<<{0}>>> MULTIPLE MATCHES:\n{1} matches q={2:p0}\n{3}", patchNum, cMatches, p.quality,
                        Useful.PatchDetails(p));
                    const int NFirst = 5;
                    Console.WriteLine("FIRST {0} MATCHES", Math.Min(NFirst, cMatches));
                    for (int i = 0; i < Math.Min(cMatches, NFirst); ++i) {
                        Console.WriteLine("#{0} at 0x{1:X8}", i + 1, matchLoc[i] + p.patchOffset);
                    }
                     if (manualLoc != 0) {
                        if (manualLoc > 0) {
                            applyAtOffset = manualLoc;
                        } else {
                            applyAtOffset = matchLoc[-1 - manualLoc] + p.patchOffset;
                        }
                    }
                } else {
                    Console.WriteLine("<<<{0}>>> NO EXACT MATCHES FOUND\n{1}", patchNum, 
                        Useful.PatchDetails(p));
                    // weighted matching: score every half-byte matching; patch bytes weigh more than surroundings. Find top scores, print top5 and their relative and absolute weights.
                    Dictionary<int, double> scores = new Dictionary<int, double>(orig.Length - match.Length);
                    double[] matchWeight = new double[match.Length];
                    double matchWeightNormalizer = 0.0;
                    for (int i = 0; i < match.Length; ++i) {
                        double weight;
                        if (i < p.patchOffset) {
                            weight = 1.0 / Math.Sqrt(p.patchOffset - i + 1);
                        }
                        else if (i < p.patchOffset + p.patchBytes.Length) {
                            weight = 1.0;
                        }
                        else {
                            weight = 1.0 / Math.Sqrt(i + 2 - (p.patchOffset + p.patchBytes.Length));
                        }

                        matchWeight[i] = weight;
                        matchWeightNormalizer += weight;
                    }
                    for (int i = 0; i < match.Length; ++i) {
                        matchWeight[i] /= matchWeightNormalizer;
                    }

                    for (int i = 0; i < orig.Length - match.Length; ++i) {
                        double score = 0.0;
                        for (int j = 0; j < match.Length; ++j) {                            
                            byte o = orig[i + j];
                            byte m = match[j];
                            double factor;
                            int x = o ^ m;
                            if (x == 0) {
                                factor = 1.0;
                            } else if (x == 0xF0 || x == 0x0F) {
                                factor = .3;
                            } else {
                                continue;
                            }
                            score += factor * matchWeight[j];
                        }
                        scores.Add(i, score);
                    }
                    const int NTop = 5;
                    var topN = scores.OrderByDescending(x => x.Value).Take(NTop).ToArray();
                    byte[] topMatchBytes = orig.Skip(topN[0].Key).Take(p.matchBytes.Length).ToArray();
                    Patch tmp = new Patch(topMatchBytes, p.patchBytes, p.patchOffset, 0);
                    bool fApplyBestBet = manualLoc == 0 && topN[0].Value * 100 >= g_confidence;
                    Console.WriteLine("TOP {0} MATCHES: TOP 1 is {1:P0}\n{2}", NTop, topN[0].Value, Useful.PatchDetails(tmp));
                    for(int i = 0; i < NTop; ++i) {
                        var x = topN[i];
                        Console.WriteLine("#{0}: {1:P0} at 0x{2:X8})", i + 1, x.Value, x.Key + p.patchOffset);
                    }
                    if (fApplyBestBet) {
                        applyAtOffset = topN[0].Key + p.patchOffset;
                    } else if (manualLoc != 0) {
                        if (manualLoc > 0) {
                            applyAtOffset = manualLoc;
                        } else {
                            applyAtOffset = topN[-1 - manualLoc].Key + p.patchOffset;
                        }
                    }

                }

                if (applyAtOffset > 0) {
                    Console.WriteLine(
                        "------------------------------\n" +
                        "++APPLIED at 0x{0:X8}", applyAtOffset);
                    Array.Copy(p.patchBytes, 0, mod, applyAtOffset, p.patchBytes.Length);
                    cApplied++;
                } else {
                    Console.WriteLine(
                        "------------------------------\n" +
                        "!!! TODO #{0} !!!", ++cTodo);                    
                }
            }

            File.WriteAllBytes(patchedPath, mod);

            Console.WriteLine(
                "\n=============================================\n" + 
                "Applied {0} of {1} patches ({2:P0})", cApplied, patches.Count, ((double)cApplied) / patches.Count);
        }

        static int g_confidence = 101;
        static Dictionary<int, int> g_overrides = new Dictionary<int, int>();

        //returns number of option arguments to skip
        static private int parseOption(string[] args, int i) {
            int cSkip = 0;
            string arg = args[i];
            switch (arg) {
                case "-c":
                case "--confidence":
                    if (!Int32.TryParse(args[i + 1], out g_confidence)) {
                    }
                    cSkip = 1;
                    break;
                default: 
                    {
                        arg = arg.Substring(1);
                        string[] parts = arg.Split(':');
                        if (parts.Length == 2) {
                            int patchNum, pos;
                            bool isIndex = false;
                            if (parts[1].StartsWith("#")) {
                                parts[1] = parts[1].Substring(1);
                                isIndex = true;
                            }
                            if (Int32.TryParse(parts[0], out patchNum) &&
                                Int32.TryParse(parts[1], out pos))
                            {
                                g_overrides.Add(patchNum, isIndex ? -pos : pos);
                            }
                        }
                    }
                    break;
            }
            return cSkip;
        }

        static void Main(string[] args) {
            List<string> optArgs = new List<string>();
            List<string> nonOptArgs = new List<string>();
            for (int i = 0; i < args.Length; ++i) {
                if (args[i].StartsWith("-")) {
                    i += parseOption(args, i);
                }
                else {
                    nonOptArgs.Add(args[i]);
                }
            }
            if (nonOptArgs.Count >= 4 &&
                "diff".Equals(nonOptArgs[0], StringComparison.OrdinalIgnoreCase)) {
                    diffFiles(nonOptArgs[1], nonOptArgs[2], nonOptArgs[3]);
            } else if (nonOptArgs.Count >= 4 &&
                "patch".Equals(nonOptArgs[0], StringComparison.OrdinalIgnoreCase)) {
                    patchFile(nonOptArgs[1], nonOptArgs[2], nonOptArgs[3]);
            } else {
                Console.WriteLine("Usage: \n\t{0} diff <orig> <patched> <diffFile>\n" + 
                "\t{0} patch <orig> <patched> <diffFile> [<options>]\n" + 
                "\tOptions:\n" + 
                "\t-c <confidence>\n" + 
                    "\t\tConfidence level for auto-applying partial matches\n"  +  
                    "\t\te.g.: -c 80 will apply patches found with 80% and higher confidence\n"  +  
                "\t-<num>:#<choice>\n" + 
                    "\t\tSelect location <choice> for a patch with <number>\n" +
                    "\t\tOverrides confidence level\n" +
                    "\t\te.g.: -3:#2 - select second location choice for patch number 3\n" +
                "\t-<num>:<offset>\n" +
                    "\t\tSpecify patch location manually\n" +
                    "\t\te.g.: -2:0x82F04C will apply patch 2 at the file offset 0x82F04C"
                , 
                    Process.GetCurrentProcess().ProcessName);
            }
        }
    }
}
