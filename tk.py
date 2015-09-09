#!encoding:utf-8
from Tkinter import *
import tkMessageBox as tb
import subprocess, sys, pexpect,os
import thread

def func(child, text, root):
    for line in child:
        print line
        text.insert(END,line)
        text.see(END)
        root.update_idletasks()

def terminate(child):
    child.close()
    text.insert(END,"terminated\n\n")
    text.see(END)
    root.update_idletasks()


def handle(filename,menu,lb):
    if os.system("cp %s config.py"%filename) == 0:
        text.insert(END, "Configure finished\n")
        text.see(END)
    else:
        raise Exception("Configure Error!")
    child = pexpect.spawn('python wind.py')
    thread.start_new(func, (child,text,root))
    if menu.type(menu.index(100)) == "command": 
        print menu.delete(sslmenu.index(100))
    menu.add_command(label=lb,command=lambda:terminate(child))


def sslPassive():
    handle("sslpassivecfg",sslmenu,"SSLPassiveStop")

def sslRepCert():
    handle("sslrepcertcfg",sslmenu,"SSLRepCertStop")

def sslFreak():
    handle("sslfreakcfg",sslmenu,"SSLFreakStop")

def ovpnPassive():
    handle("ovpnpassivecfg",ovpnmenu,"OvpnPassiveStop")



root=Tk()
root.title("The Wind")
root.geometry("1024x960")

menubar=Menu(root)

sslmenu=Menu(menubar,tearoff=0)
sslmenu.add_command(label='SSLPassive',command=sslPassive)
sslmenu.add_command(label='SSLReplaceCert',command=sslRepCert)
sslmenu.add_command(label='SSLFreak',command=sslFreak)
sslmenu.add_separator()
menubar.add_cascade(label='SSL', menu=sslmenu)

ovpnmenu=Menu(menubar,tearoff=0)
ovpnmenu.add_command(label='OvpnPassive',command=ovpnPassive)
ovpnmenu.add_separator()
menubar.add_cascade(label='OPENVPN', menu=ovpnmenu)

menubar.add_command(label='EXIT', command=root.quit)

root.config(menu=menubar)

text=Text(root, width=1024,bg='black',fg='green')
text.pack(side="left",fill='both',expand=True)
scroll=Scrollbar(root)
scroll.pack(side="right",fill='y',expand=False)
scroll.config(command=text.yview)
text.config(yscrollcommand=scroll.set)

root.mainloop()

