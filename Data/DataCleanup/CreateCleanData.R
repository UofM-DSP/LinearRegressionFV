plainText <-
  read.csv("~/Desktop/Dataset/modifiedParkinson.data", header = TRUE)
modifiedPlaintText <- plainText


#remove name field
modifiedPlaintText$name <- NULL


#remove status
colStatus <- plainText$status
modifiedPlaintText$status <- NULL

#remove spread1
colSpread1 <- plainText$spread1
modifiedPlaintText$spread1 <- NULL

#find min for +ve columns in minVal
minColVal <- apply(modifiedPlaintText, 2, min)
minVal <- 999999
for (i in minColVal) {
  if (as.numeric(i) <= minVal) {
    minVal <- i
  }
}

#get position of decimal point
decimalPoint <- 10
while ((minVal * decimalPoint) < 1) {
  decimalPoint <- decimalPoint * 10
}
print(decimalPoint)

#add spread1 field
modifiedPlaintText["spread1"] <- colSpread1

#multiply all data with decimal val
modifiedPlaintText <- data.frame(mapply(`*`, modifiedPlaintText, decimalPoint))

#convert all to integer
modifiedPlaintText <- data.frame(mapply(as.integer, modifiedPlaintText, decimalPoint))


#add status field
modifiedPlaintText["status"] <- colStatus

print("done")
write.csv(modifiedPlaintText, "~/Documents/privacyLab/linearregressionfv/linearRegression/parkinsons.data")

