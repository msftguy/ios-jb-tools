#!/usr/bin/python
from optparse import OptionParser
import sys
import os
import os.path as path
import plistlib


class BundleParser:
    def __init__(self, bundleDir, ipswDir, outDir, verbose, x_opt):
        self.x_opt = x_opt
        self.bundleDir = bundleDir
        self.ipswDir = ipswDir
        self.outDir = outDir
        self.verbose = verbose
        self.kcOrig = ""
        self.kcPatched = ""
        self.basedir = os.path.dirname(__file__) 
        self.tooldir =  self.basedir + "/tools_bin/osx/"


    def run(self, cmd, comment):
        if self.verbose:
            print "%s: %s" % (comment, cmd)
        result = os.system(cmd)
        if result != 0:
            raise Exception("Command %s failed with return code %s" % \
                            (cmd, result / 256))
    
    def fileWithSuffix(self, filePath, suffix):
        if filePath.lower().endswith('.dmg'):
            filePath = filePath[:-4]
            suffix = suffix + '.dmg'
        return path.join(self.outDir, path.basename(filePath) + suffix)	

    def unpack_file(self, filePath):
        decrypt_cmd = "%s/xpwntool %s %s" % \
            (self.tooldir, path.join(self.ipswDir, filePath), self.fileWithSuffix(filePath, '.dec'))

        self.run(decrypt_cmd, "Unpacking")

    def decrypt_file(self, filePath, iv, key):
        decrypt_cmd = "%s/xpwntool %s %s -iv %s -k %s" % \
            (self.tooldir, path.join(self.ipswDir, filePath), self.fileWithSuffix(filePath, '.dec'), iv, key)

        self.run(decrypt_cmd, "Decrypting")

    def patch_file(self, filePath, patchFile):
        patch_cmd = "bspatch %s %s %s" % \
            (self.fileWithSuffix(filePath, '.dec'), self.fileWithSuffix(filePath, '.dec.p'), path.join(self.bundleDir, patchFile))

        self.run(patch_cmd, "Patching")

    def diff_llb(self, patch, x_opt):
        filePath = patch [ 'File' ]
        patchFile = patch [ 'Patch' ]
        encrypt_cmd = "%s/xpwntool %s %s -t %s -x%s -iv %s -k %s" % \
            (self.tooldir, self.fileWithSuffix(filePath, ".dec.ap"), self.fileWithSuffix(filePath, '.ap'), \
            path.join(self.ipswDir, filePath) , x_opt , patch['IV'], patch['Key'])
        
        self.run(encrypt_cmd, "Encrypting LLB")
        
        diff_cmd = "bsdiff %s %s %s" % \
            (path.join(self.ipswDir, filePath), self.fileWithSuffix(filePath, '.ap'), path.join(self.bundleDir, patchFile))

        self.run(diff_cmd, "Diffing LLB")

            
    def ldid(self, path):
        ldid_cmd = "%s/ldid -s %s" % (self.tooldir, path)
        
        self.run(ldid_cmd, "Pseudosigning")

            
    def kpatch(self, patch, patchedPath):
        if not self.kcOrig or len(self.kcOrig) == 0:
            raise Exception("kernelcache patch needs to precede any patches using 'kpatch' attribute")
        orig = patchedPath + ".pre"
        os.rename(patchedPath, orig)
        kpatch_cmd = "%s/tools_src/ibss_kpatch/ibss_patcher.py %s %s %s %s %s/tools_bin/ios/ibss_patchproc.bin" % \
            (self.basedir, orig, patchedPath, self.kcOrig, self.kcPatched, self.basedir)

        self.run(kpatch_cmd, "Running ibss_patcher")


    def text_patch(self, patch, origPath, patchedPath):
        pattern = patch['Pattern']
        textfile = path.join(self.outDir, "_json", pattern + ".patch") 
        if not os.path.isfile(textfile):
            raise Exception("Pattern %s references a non-existing file: %s" % \
                            (pattern, textfile))
        txp_cmd = "patch -o %s %s %s" % \
            (patchedPath, origPath, textfile) 

        self.run(txp_cmd, "Patching as text")
        

    def fuzzy_patch(self, patch, origPath, patchedPath):
        pattern = patch['Pattern']
        jsonfile = path.join(self.outDir, "_json", pattern + ".patch.json") 
        if not os.path.isfile(jsonfile):
            self.text_patch(patch, origPath, patchedPath)
            return
        
        fzp_cmd = "%s/fuzzy_patcher --fuzz 80 --patch --orig %s --patched %s --delta %s" % \
            (self.tooldir, origPath, patchedPath, jsonfile) 
        
        self.run(fzp_cmd, "Fuzzy patching")
        
        if pattern.lower().startswith("kernel"):
            self.kcOrig = origPath
            self.kcPatched = patchedPath

        if 'kpatch' in patch:
            self.kpatch(patch, patchedPath)

        # TODO: MACH binary detection?
        if not path.basename(origPath).startswith('asr'):
            return
        self.ldid(patchedPath)
            
    def diff_file(self, patch, isFirmwarePatch):
        filePath = patch['File']

        if isFirmwarePatch:
            orig_suffix = '.dec'
            ap_suffix = '.dec.ap'
        else:
            orig_suffix = ''
            ap_suffix = '.ap'
        
        origPath = self.fileWithSuffix(filePath, orig_suffix)
        patchedPath = self.fileWithSuffix(filePath, ap_suffix)
        
        if 'Pattern' in patch:
            self.fuzzy_patch(patch, origPath, patchedPath)
        
        if not 'Patch' in patch: # could be a kc entry without actual patch file
            return
        
        patchFile = patch['Patch']
            
        if path.basename(filePath).startswith('LLB') and self.x_opt:
            self.diff_llb(patch, self.x_opt)
            return 

        diff_cmd = "bsdiff %s %s %s" % \
            (origPath, patchedPath, path.join(self.bundleDir, patchFile)) 

        self.run(diff_cmd, "Diffing")

    def decrypt_rootfs(self):
        key = self.infoPlist['RootFilesystemKey']
        dmg = self.infoPlist['RootFilesystem']
        
        vfdecrypt_cmd = "%s/vfdecrypt -i %s -o %s -k %s" % \
            (self.tooldir, path.join(self.ipswDir, dmg), self.fileWithSuffix(dmg, '.dec'), key)
            
        self.run(vfdecrypt_cmd, "vfdecrypt")
                
        mount_cmd = "hdiutil attach %s" % self.fileWithSuffix(dmg, '.dec')
        
        self.run(mount_cmd, "hdiutil")


    def fspatch_extract_callback(self, patch):
        if not 'Patch' in patch and not 'Pattern' in patch:
            return
        filePath = patch['File']
        mountpoint = path.join('/Volumes', self.infoPlist['RootFilesystemMountVolume'])
        cp_cmd = "cp %s %s" % (path.join(mountpoint, filePath), self.fileWithSuffix(filePath, ""))

        self.run(cp_cmd, "cp")	

    def mount_ramdisk(self):
        firmwarePatches = self.infoPlist['FirmwarePatches']
        if not 'Restore Ramdisk' in firmwarePatches:
            return
        patch = firmwarePatches['Restore Ramdisk']
        filePath = patch['File']
        
        mount_cmd = "hdiutil attach %s" % self.fileWithSuffix(filePath, '.dec')
        
        self.run(mount_cmd, "hdiutil")

    def fwpatch_decrypt_callback(self, patch, patchKey):
        if not 'IV' in patch:
            self.unpack_file(patch['File'])
        else:
            self.decrypt_file(patch['File'], patch['IV'], patch['Key'])
        if 'Patch' in patch:
            self.patch_file(patch['File'], patch['Patch'])	

    def genpatch_create_callback(self, patch):
        if 'Patch' in patch:
            self.diff_file(patch, isFirmwarePatch = False)

    def fwpatch_create_callback(self, patch, patchKey):
        if 'Patch' in patch or 'Pattern' in patch:
            self.diff_file(patch, isFirmwarePatch = True)

    def foreach_fwpatch(self, callback):
        firmwarePatches = self.infoPlist['FirmwarePatches']
        keys = firmwarePatches.keys()
        keys.sort()
        for patchKey in keys:
            patch = firmwarePatches[patchKey]
            callback(patch, patchKey)

    def foreach_fspatch(self, callback):			
        filesystemPatches = self.infoPlist['FilesystemPatches']
        for patchGroupKey in filesystemPatches:
            patchGroup = filesystemPatches[patchGroupKey]
            for patch in patchGroup:
                callback(patch)

    def rdpatch_extract_callback(self, patch):
        filePath = patch['File']
        ramdiskKey = None
        for key in ['RestoreRamdiskMountVolume','RamdiskMountVolume']:
            if key in self.infoPlist:
                ramdiskKey = key
                break
        if not ramdiskKey:
            return
        mountpoint = path.join('/Volumes', self.infoPlist[ramdiskKey])
        cp_cmd = "cp %s %s" % (path.join(mountpoint, filePath), self.fileWithSuffix(filePath, ""))
        
        self.run(cp_cmd, "cp")	

    def foreach_rdpatch(self, callback):
        rdPatches = self.infoPlist['RamdiskPatches']
        for rdKey in rdPatches:
            patch = rdPatches[rdKey]
            callback(patch)

    def umount_all(self):
        for key in ['RamdiskMountVolume', 'RestoreRamdiskMountVolume', 'RootFilesystemMountVolume']:
            if not key in self.infoPlist:
                continue
            mountpoint = path.join('/Volumes', self.infoPlist[key])
            
            umount_cmd = "hdiutil detach %s" % mountpoint
            
            self.run(umount_cmd, "Unmount")			

    def process_info_plist(self):
        self.infoPlist = plistlib.readPlist(path.join(self.bundleDir, 'Info.plist'))
        
        self.foreach_fwpatch(self.fwpatch_decrypt_callback)
        
        self.mount_ramdisk()
        
        self.foreach_rdpatch(self.rdpatch_extract_callback)
                                                        
        self.decrypt_rootfs()
        
        self.foreach_fspatch(self.fspatch_extract_callback)

        self.umount_all()

    def create_patch_files(self):
        self.infoPlist = plistlib.readPlist(path.join(self.bundleDir, 'Info.plist'))

        self.foreach_fwpatch(self.fwpatch_create_callback)

        self.foreach_rdpatch(self.genpatch_create_callback)

        self.foreach_fspatch(self.genpatch_create_callback)
	
def main():
    parser = OptionParser()
    parser.add_option("-b", "--bundle", dest="bundle", help="Bundle directory to use", metavar="BUNDLE_DIR")
    parser.add_option("-i", "--ipsw", dest="ipsw", help="Unpacked IPSW directory", metavar="IPSW_DIR")
    parser.add_option("-o", "--out", dest="out", help="Output directory", metavar="OUT_DIR")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose mode")
    parser.add_option("-c", "--create", dest="create", action="store_true", default=False, help="Create patch files from work dir")
    parser.add_option("-x", "--llbexploit", dest="x_opt", default=None, help="Type of LLB exploit to use, n8824k or 24k")

    (opts, args) = parser.parse_args()
    requiredOpts = ['bundle', 'ipsw', 'out']
    for req in requiredOpts:
        if not opts.__dict__[req]:
            print "'%s' argument is mandatory!" % req
            exit(1)
    bundleParser = BundleParser( opts.bundle, opts.ipsw, opts.out, opts.verbose, opts.x_opt)
    if opts.create:
        bundleParser.create_patch_files()
    else:
        bundleParser.process_info_plist()

if __name__ == "__main__":
    main()
