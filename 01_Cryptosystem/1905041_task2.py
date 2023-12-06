import time
import secrets
import importlib
ecdh = importlib.import_module("1905041_ecdh")

key_sizes = [128, 192, 256]

print("\t\t\tComputation Time For")
print("\tk")
print("\t\t\tA\t\tB\tshared key R")
for bitsize in key_sizes:
    print("\t", bitsize, end="")
    time_A = 0
    time_B = 0
    time_R = 0
    for i in range(5):
        worker = ecdh.ECDH_client(bitsize)
        (curve, G) = worker.mk_curve_and_gen_point(bitsize)
        start_time = time.time_ns()
        (private_key_A, public_key_A) = worker.mk_keys(curve, G)
        time_A = time_A + (time.time_ns() - start_time) / (10**6)

        start_time = time.time_ns()
        (private_key_B, public_key_B) = worker.mk_keys(curve, G)
        time_B = time_B + (time.time_ns() - start_time) / (10**6)

        start_time = time.time_ns()
        worker.mk_shared_secret(public_key_A, private_key_B)
        time_R = time_R + (time.time_ns() - start_time) / (10**6)

    print("\t", round(time_A/5,4), " ms\t", round(time_B/5, 4), " ms\t", round(time_R/5, 4), " ms")
