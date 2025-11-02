import random 
import datetime
def randomquotes(quotes_list) :
    today = datetime.date.today().toordinal()
    random.seed(today)
    return random.choice(quotes_list)