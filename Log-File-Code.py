import datetime

current_time = str(datetime.datetime.now())
current_time = current_time.replace("-", "_")
current_time = current_time.replace(":", "-")
log_file = open((current_time + ".txt"), "x")
log_file.write("Yipee it worked")
log_file.close()