from i2clibraries import i2c_adxl345
from time import*
import os

os.system("clear")

adxl345 = i2c_adxl345.i2c_adxl345(0)
adxl345.setInactivityTime(sec=1000)
(x,y,z) = adxl345.getAxes()

count = 1

while True: 
    (x,y,z) = adxl345.getAxes()
    print("Count: " + str(count))

    print("\n")
    print("X: " + str(x))
    print("\n")
    print("Y: " + str(y))
    print("\n")
    print("Z: " + str(z))
    print("\n")

    sleep(1)

    count+=1
    os.system("clear")

