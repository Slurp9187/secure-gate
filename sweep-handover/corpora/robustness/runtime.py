import resource, subprocess, sys, time
cmd = sys.argv[1:]
t0 = time.time()
r = subprocess.run(cmd, capture_output=True, text=True)
wall = time.time() - t0
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
print("WALL=%.1fs MAXRSS=%.0fMB EXIT=%d" % (wall, ru.ru_maxrss/1024, r.returncode))
print("STDOUT:", r.stdout[-2000:])
print("STDERR:", r.stderr[-2000:])
