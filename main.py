import warnings
import getpass
import json
import sys
import requests
import csv    
import os



res= None #Variable used to make the auth request
auth_path = "/api/fmc_platform/v1/auth/generatetoken" #Variable that stores the API authentication path
headers = {'Content-Type': 'application/json'}
auth_url = None
fmc_url = None
ans = []
FMC_IP = None
username = None
password = None
group_name = None
    


ans = input ("This Python Script allows you to create Network Object Groups\nWould you like to continue? (Y|N)\t")
ans = ans.lower().strip()

if not ans:
    quit()
elif ans[0] == "y":
    ()
else:
    quit()

#Ignore not valid certificate warning
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# FMC IP address request
while not FMC_IP:
    FMC_IP = input("\nPlease enter FMC IP address: ")

# #FMC user and password request
# print("\nPlease provide username and password to authenticate")

while not username:
    username = input("\nUsername: ")

while not password:
    password = getpass.getpass("\nPassword: ")


auth_url ="https://" + FMC_IP + auth_path #Variable that stores authentication URL

fmc_url = "https://" + FMC_IP #Variable that stores FMC URL


try:
    print("\n\nConnecting to FMC")
    requests.packages.urllib3.disable_warnings()
    res = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    auth_headers = res.headers
    auth_token = auth_headers.get("X-auth-access-token", default=None)#Code to get auth token
    print(f"auth token: {auth_token}")
    if auth_token == None:
        print("\nAuthentication token not found, ending process...")
        sys.exit()
except Exception as err:
    print ("\nError while generating authentication token--> "+str(err))
    sys.exit()
headers["X-auth-access-token"] = auth_token

print("\n\nConnected, your authentication token is:\t\t" + auth_token)

#Get Network Addresses
net_url = fmc_url+"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkaddresses?offset=0&limit=100000"

#Post Network Group
group_url =fmc_url+"/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups"

#Read the file  that contains the objects that are part of the network group, this shoud be a .csv file
#The file should be on the same directory as this script
#The file should contain a colum named name

fName_request = input('\n\nPlease enter the file name for the file storing the Network Group Elements:\t\t')
open_csv = os.path.join(os.path.dirname(__file__))+"\\"+fName_request

csvfile = open(open_csv,mode='r')
objects = csv.DictReader(csvfile)

try:
    print("\n\nGetting Network Object List ...")
    requests.packages.urllib3.disable_warnings()
    #This is for Network Address Objects
    get_net = requests.get(net_url,headers=headers,verify=False)
    net_list = get_net.text
    net_json = json.loads(net_list)

    group_objects = []

    for objects in objects:
        for net_names in net_json["items"]:
            if objects["name"] == net_names ["name"]:
                #Here you obtain the name of the object, the type, and the id of the object, then it's stored inside the group objects variable
                group_objects.append({"type" : net_names["type"] , "name" : net_names["name"] , "id" : net_names["id"]})
    
    while not group_name:
        group_name = input("\nPlease enter the group name: ")
    #The data used to configure the network group    
    post_data = {
        "name": group_name,
        "objects": group_objects,
        "type": "NetworkGroup"
        }
    
    r = requests.post(group_url, data=json.dumps(post_data), headers=headers, verify=False)
    status_code = r.status_code
    #I should improve the code here but this works
    if status_code == 201 or status_code == 202:
        print("good")
    elif status_code == 400:
        print("poor")
    else:
        print("bad")

except Exception as err:
    print ("\nError while generating authentication token--> "+str(err))
    sys.exit()
