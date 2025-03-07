import math
from decimal import *
getcontext().prec = 3 # set up 3 significant digits

norm = "canonical norm"

# set up parameters
N = 2**15
q = 2**881
p = q
t = 2**16

# N = 2**14
# q = 2**438
# p = q
# t = 2**30

# N = 2**13
# q = 2**218
# t = 2**30

print ("BFV system parameters: logN =",int(math.log(N,2)), " logq =", int(math.log(q,2)), " logt =", int(math.log(t,2)))

sigma_rlk = Decimal(3.2)
h = Decimal(10.0)

if norm == "infinity norm":
	# use infinity norm for analysis
	sigma_0 = Decimal((2*N+1) * (3.2*3.2) + t*t/12).sqrt()

elif norm == "canonical norm":
	# or use canonical norm for analysis
	sigma_0 = Decimal(6*math.sqrt(N)*t/math.sqrt(12))

sigma_1 = Decimal(sigma_0)


sigma_mul = sigma_0

for i in range(30):
	w = t * (sigma_mul)/q
	noise_budget = -1*((2*w).ln()/Decimal(2).ln())
	print ("multiplicative depth = ", i, " sigma_mul = ", sigma_mul, " noise_budget = ", noise_budget)

	if norm == "infinity norm":
	# use infinity norm for analysis
	# sigma_mul = ( N*t*t*sigma_0*sigma_0/12 + N*t*t*sigma_1*sigma_1/12 + t*t*N*sigma_0*sigma_0*sigma_1*sigma_1/(q*q) + N*t*t*t*t/Decimal(12*12) + N*t*t*t*t*sigma_0*sigma_0/(q*q*12) + N*t*t*t*t*sigma_1*sigma_1/(q*q*12) + N*sigma_rlk*sigma_rlk/12 + N*h/12 ).sqrt()
		sigma_mul = ( N*t*t*sigma_0*sigma_0/12 + N*t*t*sigma_1*sigma_1/12 + t*t*N*sigma_0*sigma_0*sigma_1*sigma_1/(q*q) + t*t*t*t/Decimal(12*12) ).sqrt()
	elif norm == "canonical norm":
	# or use canonical norm for analysis
		# sigma_mul = ( N*N*t*t*sigma_0*sigma_0 + N*N*t*t*sigma_1*sigma_1 ).sqrt()
		sigma_mul = 16*N*t*sigma_0/Decimal(math.sqrt(12)) + 16*N*t*sigma_1/Decimal(math.sqrt(12)) + Decimal(N*t*t/12)

	sigma_0 = sigma_mul
	sigma_1 = sigma_mul

	
	if (sigma_mul > q/(2*t)): # if noise overflows, quit
		break