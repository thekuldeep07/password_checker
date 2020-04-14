import requests
import sys
import hashlib

def request_api_data(querry_char):
    url='https://api.pwnedpasswords.com/range/'+ querry_char
    res=requests.get(url)
    if res.status_code !=200:
        raise RuntimeError(f'error fetching :{re.status_code},check the api and try again')
    return res
def get_password_leak_count(hashes,hash_to_check):
    hashes=(line.split(':') for line in hashes.text.splitlines())
    for h,count in hashes:
        if hash_to_check in h:
            print(h)
            return count
    return 0
def  pwned_api_check(password):
    sha1password=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char,tail=sha1password[:5],sha1password[5:]
    response=request_api_data(first5_char)
    return get_password_leak_count(response,tail)
def main(args):
    for password in args:
        count=pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times..... '
                  f'you should probably change your password')
        else:
            print(f' hurray password was not found carry on!!!!!!')
    return 'done!!!!'
if __name__ =='__main__':
    sys.exit(main(sys.argv[1:]))