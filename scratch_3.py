import vhdmount.diskpart as vdisk
import os


# vhdfile=os.path.abspath("vhdfile-10mb.vhd")
# last_volumn_index = vdisk.diskpart_attach_vdisk(vhdfile)
# vdisk.diskpart_assign_letter(last_volumn_index,"f")
# vdisk.diskpart_unmount(vhdfile,last_volumn_index)

folderpath=os.path.abspath(".")
filename="encryptfile-100mb.vhd"
fullpath=os.path.join(folderpath,filename)
vdisk.diskpart_create_vdisk(fullpath,100,True)
