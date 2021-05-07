/// <author>
/// Abigail Merino (avm9767)
/// </author>
/// <summary>
/// Project 3: A simple messaging client that uses RSA encryption
/// </summary>

using System;
using System.IO;                    // Directory & File
using System.Text;                  // Encoding
using System.Numerics;              // BigInteger
using System.Collections.Generic;   // List
using System.Threading.Tasks;       // Parallel.For
using System.Security.Cryptography; // RNGCryptoServiceProvider
using System.Net.Http;              // HTTPClient
using System.Text.Json;             // JsonSerializer

using ExtensionMethods;

namespace Project3
{
    /// <summary>
    /// Contains the access point for the program.
    /// </summary>
    class Program
    {

        /// <summary>
        /// The main method. Runs the prime generator.
        /// </summary>
        /// <param name="args">List of command line arguments</param>
        static void Main(string[] args)
        {
            var prog = new Program();

            try
            {
                bool isValid = prog.ValidateArguments(args);
                if (!isValid) prog.PrintHelp();
            }
            catch
            {
                prog.PrintHelp();   // if any other weird errors pop up, print help
            }

            prog.RunMessenger(args);
        }

        /// <summary>
        /// Quick validation of command line arguments. Checks if number of arguments 
        /// are correct as well as very shallow validation. More in-depth parameter 
        /// checking will be done later
        /// </summary>
        /// <param name="args">the command line arguments</param>
        /// <returns>true if the arguments are valid, else false</returns>
        public bool ValidateArguments(string[] args)
        {
            var command = args[0].ToLower();
            switch (command)
            {
                case "keygen":  
                    if (args.Length != 2) return false;  // should only be 2 arguments
                    int keysize = Int32.Parse(args[1]);
                    if (keysize < 32 || keysize % 8 != 0)
                    {
                        // keysize must be divisible by 8
                        return false;
                    }
                    break;

                case "sendkey": // requires 1 argument: email
                case "getkey":
                case "getmsg":
                    if (args.Length != 2) return false;  // should only be 2 arguments
                    break;

                case "sendmsg": // requires 2 arguments: email & plaintext
                    if (args.Length != 3) return false;  // should only be 3 arguments
                    break;

                default:        // return an error
                    return false;
            }

            return true;
        }

        /// <summary>
        /// The main calling function that directs to the method that the user 
        /// specified in the command line.
        /// </summary>
        /// <param name="args">the command line arguments</param>
        public void RunMessenger(string[] args)
        {
            MessengerClient client = new MessengerClient();
            var command = args[0].ToLower();

            try
            {
                switch (command)
                {
                    case "keygen":
                        int keysize = Int32.Parse(args[1]);
                        client.GenerateKey(keysize);
                        break;

                    case "sendkey":
                        client.SendKey(args[1]);
                        break;

                    case "getkey":
                        client.GetKey(args[1]);
                        break;

                    case "getmsg":
                        client.GetMessage(args[1]);
                        break;

                    case "sendmsg":
                        client.SendMessage(args[1], args[2]);
                        break;
                }
            }
            catch (MessengerException ex)
            {
                Console.WriteLine(ex.Message);  // will print our custom error messages
                System.Environment.Exit(1);
            }
        }

        /// <summary>
        /// Prints the help message if invalid arguments are given.
        /// </summary>
        public void PrintHelp()
        {
            string helpMsg = "\ndotnet run <option> <arguments>"
                           + "\nOptions: \n"
                           + "    * keyGen <keysize> - generates a keypair of size 'keysize' bits. Must be a multiple of 8.\n"
                           + "    * sendKey <email> - sends the public key to the server, associating the given email to it.\n"
                           + "    * getKey <email> - retrieves the public key for the user associated with the given email.\n"
                           + "    * sendMsg <email> <plaintext> - encryptes & sends the given message to the user of the specified email.\n"
                           + "    * getMsg <email> - retrieves & decryptes a message from the user of the specified email.\n";
            Console.WriteLine(helpMsg);
            System.Environment.Exit(1);
        }
    }

    /// <summary>
    /// The class responsible for generating prime numbers. 
    /// </summary>
    class PrimeGenerator
    {
        private readonly object countLock = new object();

        /// <summary>
        /// Default PrimeGenerator constructor.
        /// </summary>
        public PrimeGenerator() { }

        /// <summary>
        /// Generates and returns the required number of primes.
        /// </summary>
        /// <param name="count">the number of primes to generate</param>
        /// <param name="bitLength">the number of bits each prime should be</param>
        /// <returns>a list of BigInteger primes</returns>
        public List<BigInteger> Generate(int count, int bitLength)
        {
            int bytes = bitLength / 8;
            var rng = new RNGCryptoServiceProvider();
            List<BigInteger> primes = new List<BigInteger>();
            int currCount = 0;

            Parallel.For(0, Int32.MaxValue, (i, state) =>
            {

                Byte[] num_bytes = new Byte[bytes];
                rng.GetBytes(num_bytes);
                BigInteger num = new BigInteger(num_bytes);

                // since isProbablyPrime() doesn't like to work with numbers < 5, 
                // we'll just manually check them beforehand
                bool isPrime = false;
                if (num == 2 || num == 3)
                    isPrime = true;
                else if (num % 2 != 0)      // quick check if num is even
                    isPrime = num.IsProbablyPrime();

                if (isPrime)
                {
                    lock (countLock)
                    {
                        if (!state.IsStopped)
                        {
                            currCount++;
                            primes.Add(num);

                            if (currCount == count)
                            {
                                state.Stop();   // stop once we found all required primes
                            }
                        }  // once state.isStopped == true, the already-running tasks will fall through
                    }
                }

            });

            return primes;
        }

    }

    /// <summary>
    /// The class responsible for generating RSA keys.
    /// </summary>
    public class KeyGenerator
    {
        private int bitLength = 0;

        /// <summary>
        /// Constructor for KeyGenerator.
        /// </summary>
        /// <param name="numBits">the number of bits the keys should add up to</param>
        public KeyGenerator(int numBits)
        {
            bitLength = numBits;
        }

        /// <summary>
        /// Generates the public and private keys.
        /// </summary>
        /// <returns>an RSA object, which holds both keys</returns>
        public RSA Generate()
        {
            PrimeGenerator generator = new PrimeGenerator();
            List<BigInteger> primes = generator.Generate(2, bitLength/2);

            BigInteger N = primes[0] * primes[1];
            BigInteger phi_N = (primes[0] - 1) * (primes[1] - 1);
            BigInteger E = generator.Generate(1, 16)[0];
            BigInteger D = E.ModInverse(phi_N);

            return new RSA(E, N, D);
        }

    }

    /// <summary>
    /// The class responsible for RSA encryption & decryption.
    /// </summary>
    public class RSA
    {
        public string privateKey { get; set; }  // base64 string
        public string publicKey { get; set; }   // base64 string

        /// <summary>
        /// Default RSA constructor.
        /// </summary>
        public RSA() { }

        /// <summary>
        /// RSA constructor that takes in base numbers and returns complete 
        /// and encoded keys.
        /// </summary>
        /// <param name="E">public number e</param>
        /// <param name="N">public number n</param>
        /// <param name="D">private number d</param>
        public RSA(BigInteger E, BigInteger N, BigInteger D)
        {
            string[] keys = FinalizeKeys(E, N, D);
            privateKey = keys[0];
            publicKey = keys[1];
        }

        /// <summary>
        /// Finalizes the generated keys by properly encoding them.
        /// </summary>
        /// <param name="num_E">public number e</param>
        /// <param name="num_N">public number n</param>
        /// <param name="num_D">private number d</param>
        /// <returns>an array of 2 encoded keys: [0] = private, [1] = public</returns>
        private string[] FinalizeKeys(BigInteger num_E, BigInteger num_N, BigInteger num_D)
        {
            byte[] E = num_E.ToByteArray();
            byte[] N = num_N.ToByteArray();
            byte[] D = num_D.ToByteArray();

            int len_E = Buffer.ByteLength(E);
            int len_N = Buffer.ByteLength(N);
            int len_D = Buffer.ByteLength(D);

            byte[] e_buff = BitConverter.GetBytes(len_E);
            byte[] n_buff = BitConverter.GetBytes(len_N);
            byte[] d_buff = BitConverter.GetBytes(len_D);

            // switch little e, little n, & little d to big endian
            Array.Reverse(e_buff);
            Array.Reverse(n_buff);
            Array.Reverse(d_buff);

            byte[] public_Key = new byte[8 + len_E + len_N];
            byte[] private_Key = new byte[8 + len_D + len_N];

            // first copy everything into the public key
            e_buff.CopyTo(public_Key, 0);
            E.CopyTo(public_Key, e_buff.Length); // e, n, d should always equal 4
            n_buff.CopyTo(public_Key, e_buff.Length + E.Length);
            N.CopyTo(public_Key, e_buff.Length + E.Length + n_buff.Length);

            // now the private key
            d_buff.CopyTo(private_Key, 0);
            D.CopyTo(private_Key, d_buff.Length); // e, n, d should always equal 4
            n_buff.CopyTo(private_Key, d_buff.Length + D.Length);
            N.CopyTo(private_Key, d_buff.Length + D.Length + n_buff.Length);

            return new string[] { Encode(private_Key), Encode(public_Key) };
        }

        /// <summary>
        /// Decodes and grabs the base values embedded in the key (i.e. E, N, and/or D).
        /// </summary>
        /// <param name="key">the key to grab values from</param>
        /// <returns>a BigInteger array containing the values: [0] = E/D, [1] = N</returns>
        private BigInteger[] GetKeyValues(string key)
        {
            byte[] decoded = Decode(key);
            byte[] e_or_d = new byte[4];
            Array.Copy(decoded, e_or_d, 4);

            Array.Reverse(e_or_d);  // convert number back to little endian
            int firstNum = BitConverter.ToInt32(e_or_d); 
            byte[] E_or_D_buff = new byte[firstNum];

            for (int i = 4, n = 0; i < 4 + firstNum; i++, n++)
            {
                E_or_D_buff[n] = decoded[i];
            }
            BigInteger E_or_D = new BigInteger(E_or_D_buff);

            byte[] n_buff = new byte[4];
            for (int i = 4 + firstNum, n = 0; i < 8 + firstNum; i++, n++)
            {
                n_buff[n] = decoded[i];
            }
            Array.Reverse(n_buff);  // change it back to little endian
            int secondNum = BitConverter.ToInt32(n_buff);

            byte[] N_buff = new byte[secondNum];
            for (int i = 8 + firstNum, n = 0; i < decoded.Length; i++, n++)
            {
                N_buff[n] = decoded[i];
            }
            BigInteger N = new BigInteger(N_buff);

            return new BigInteger[] { E_or_D, N };
        }

        /// <summary>
        /// Encrypts a plaintext into a base64 ciphertext.
        /// Takes in a normal string and returns a base64 (encrypted) string.
        /// </summary>
        /// <param name="plaintext">the message to encrypt</param>
        /// <returns>the encrypted ciphertext as a base64 string</returns>
        public string EncryptMessage(string plaintext)
        {
            BigInteger[] public_key;
            try
            {
                public_key = GetKeyValues(publicKey);
            } 
            catch 
            {
                throw new MessengerException("Error occurred while extracting key values. Are you sure the key is implemented correctly?");
            }
            BigInteger E = public_key[0];
            BigInteger N = public_key[1];

            byte[] msg_buff = Encoding.UTF8.GetBytes(plaintext);
            BigInteger msg = new BigInteger(msg_buff);

            BigInteger ciphertext = BigInteger.ModPow(msg, E, N);
            byte[] cipher_buff = ciphertext.ToByteArray();

            return Encode(cipher_buff);
        }

        /// <summary>
        /// Decodes and decryptes a ciphertext into its original plaintext.
        /// Takes in a base64 (encrypted) string and returns a normal string.
        /// </summary>
        /// <param name="ciphertext">the message to decrypt</param>
        /// <returns>the decrypted plaintext</returns>
        public string DecryptMessage(string ciphertext)
        {
            BigInteger[] private_key;
            try
            {
                private_key = GetKeyValues(this.privateKey);
            }
            catch 
            {
                throw new Exception("Error occurred while extracting key values. Are you sure the key is implemented correctly?");
            }
            BigInteger D = private_key[0];
            BigInteger N = private_key[1];

            byte[] cipher_buff = Decode(ciphertext);
            BigInteger cipher = new BigInteger(cipher_buff);

            BigInteger plaintext = BigInteger.ModPow(cipher, D, N);
            byte[] msg_buff = plaintext.ToByteArray();

            return Encoding.UTF8.GetString(msg_buff); 
        }

        /// <summary>
        /// Encodes a byte array into a base64 string.
        /// </summary>
        /// <param name="str">the byte array to encode</param>
        /// <returns>a base64 string</returns>
        private string Encode(byte[] str)
        {
            string encoded = null;
            try
            {
                encoded = Convert.ToBase64String(str);
            }
            catch 
            {
                throw new MessengerException("An error occurred while encoding the key.");
            }

            return encoded;
        }

        /// <summary>
        /// Decodes a base64 string into a byte array.
        /// </summary>
        /// <param name="str">the string to decode</param>
        /// <returns>a byte array</returns>
        private byte[] Decode(string str)
        {
            byte[] decoded = null;
            try
            {
                decoded = Convert.FromBase64String(str);
            }
            catch 
            {
                throw new MessengerException("An error occurred while decoding the key.");
            }

            return decoded;
        }
    }

    /// <summary>
    /// The class responsible for interacting with the server.
    /// </summary>
    public class MessengerClient
    {
        private static string baseUrl = "http://kayrun.cs.rit.edu:5000/";
        private static string MSG_URI = "Message/{0}";
        private static string KEY_URI = "Key/{0}";
        private string currDir = Directory.GetCurrentDirectory();
        HttpClient client;

        /// <summary>
        /// A basic class that represents the equivalent of the JSON private key.
        /// </summary>
        class PrivateKey
        {
            public List<string> email { get; set; }
            public string key { get; set; }
        }

        /// <summary>
        /// A basic class that represents the equivalent of the JSON public key.
        /// </summary>
        class PublicKey
        {
            public string email { get; set; }
            public string key { get; set; }
        }

        /// <summary>
        /// A basic class that represents the equivalent of the JSON message.
        /// </summary>
        class Message
        {
            public string email { get; set; }
            public string content { get; set; }
        }

        /// <summary>
        /// Default MessengerClient constructor.
        /// </summary>
        public MessengerClient() {
            client = new HttpClient();
        }
        
        /// <summary>
        /// An async helper function for the methods that use a GET call. 
        /// Mostly helps control the call stack for GetAsync() to make sure
        /// everything is happening in order (synchronous).
        /// </summary>
        /// <param name="email">the email to send to the server</param>
        /// <param name="uri">the URL extension being accessed</param>
        /// <returns>the response as a JSON string</returns>
        private async Task<string> GET(string email, string uri)
        {
            Uri url = new Uri(baseUrl + String.Format(uri, email));
            try
            {
                HttpResponseMessage response = await client.GetAsync(url);
                if (response.IsSuccessStatusCode) return await response.Content.ReadAsStringAsync();
                else return null;   // this means the email doesn't exist
            }
            catch
            {
                return null;    // this means an error occurred of some type
            }
        }

        /// <summary>
        /// An async helper function for the methods that use a PUT call. 
        /// Mostly helps control the call stack for PutAsync() to make sure
        /// everything is happening in order (synchronous).
        /// </summary>
        /// <param name="email">the email to send to the server</param>
        /// <param name="uri">the URL extension being accessed</param>
        /// <param name="json">the request body</param>
        /// <returns>true/false whether the request was successful</returns>
        private async Task<bool> PUT(string email, string uri, string json)
        {
            Uri url = new Uri(baseUrl + String.Format(uri, email));
            try {
                StringContent content = new StringContent(json, Encoding.UTF8, "application/json");
                HttpResponseMessage response = await client.PutAsync(url, content);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Generates and saves the public and private keys according to the keysize given.
        /// </summary>
        /// <param name="keysize">the total size of the keys</param>
        public void GenerateKey(int keysize)
        {
            // generate keys
            KeyGenerator generator = new KeyGenerator(keysize);
            RSA keys = generator.Generate();
            var pr_key = new PrivateKey() { email = { }, key = keys.privateKey };
            var pub_key = new PublicKey() { email = "", key = keys.publicKey };

            // save the keys into a file
            string json_pr = JsonSerializer.Serialize(pr_key);
            string json_pub = JsonSerializer.Serialize(pub_key);

            SaveKeyToFile("private.key", json_pr);
            SaveKeyToFile("public.key", json_pub);
        }

        /// <summary>
        /// Sends the public key to the server under the identity of the given email.
        /// Saves the specified email as a valid user for the local private key.
        /// </summary>
        /// <param name="email">the email to register</param>
        public void SendKey(string email)
        {
            // grab our local private & public keys
            string private_json = ReadKeyFromFile("private.key");
            string public_json = ReadKeyFromFile("public.key");
            if (private_json == null || public_json == null)
            {
                // this means the keys haven't been generated yet
                throw new MessengerException("Public & private keys are missing. Use 'keyGen' to generate them.");
            }

            var private_key = JsonSerializer.Deserialize<PrivateKey>(private_json);
            var public_key = JsonSerializer.Deserialize<PublicKey>(public_json);
            public_key.email = email;
            var json = JsonSerializer.Serialize(public_key);

            // send public key to email
            bool sentSuccessfully = PUT(email, KEY_URI, json).Result;
            if (!sentSuccessfully) throw new MessengerException("Error occurred while sending key to server.");

            // add email to list of emails in private.key
            if (private_key.email == null) private_key.email = new List<string>();
            if (!private_key.email.Contains(email)) private_key.email.Add(email);
            SaveKeyToFile("private.key", JsonSerializer.Serialize(private_key));

            client.Dispose();
            Console.WriteLine("Key saved");
        }

        /// <summary>
        /// Grabs and saves the public key of the specified email.
        /// </summary>
        /// <param name="email">the email to get the public key of</param>
        public void GetKey(string email)
        {
            string response = GET(email, KEY_URI).Result;
            if (String.IsNullOrWhiteSpace(response)) // either error or doesn't exist
            {
                client.Dispose();
                throw new MessengerException($"Email '{email}' does not exist.");
            }

            SaveKeyToFile($"{email}.key", response);
            client.Dispose();
        }

        /// <summary>
        /// Sends an encrypted & encoded message to the specified user (email).
        /// </summary>
        /// <param name="email">the email of the recipient</param>
        /// <param name="plaintext">the message to send</param>
        public void SendMessage(string email, string plaintext)
        {
            // first check that you have the email's public key
            string json = ReadKeyFromFile($"{email}.key");
            if (json == null) throw new MessengerException($"Key does not exist for {email}");

            // then encode message
            PublicKey pub = JsonSerializer.Deserialize<PublicKey>(json);
            RSA rsa = new RSA() { publicKey = pub.key };
            string ciphertext = rsa.EncryptMessage(plaintext);

            // now send to server
            Message msg = new Message() { email = email, content = ciphertext };
            string msg_json = JsonSerializer.Serialize(msg);
            bool sentSuccessfully = PUT(email, MSG_URI, msg_json).Result;
            if (!sentSuccessfully) throw new MessengerException("Error occurred while sending message");

            client.Dispose();
            Console.WriteLine("Message written");
        }

        /// <summary>
        /// Gets a message from the server tied to the specified email.
        /// </summary>
        /// <param name="email">the email to grab the message from</param>
        public void GetMessage(string email)
        {
            // first check if email is one of our own
            string key_str = ReadKeyFromFile("private.key");
            if (key_str == null)
            {
                // this means the keys haven't been generated yet
                throw new MessengerException("Public & private keys are missing. Use 'keyGen' to generate them.");
            }

            PrivateKey key = JsonSerializer.Deserialize<PrivateKey>(key_str);
            bool emailBelongs = key.email.Contains(email);
            if (!emailBelongs)
            {
                // not one of our emails, therefore we should not be able to decrypt
                throw new MessengerException($"'{email}' is not registered to your private key. Cannot decode message.");
            }

            // get the message
            string response = GET(email, MSG_URI).Result;
            if (String.IsNullOrWhiteSpace(response)) // either error or doesn't exist
            {
                client.Dispose();
                throw new MessengerException("No messages from server.");
            }
            client.Dispose();

            // now decrypt the message & print
            var msg = JsonSerializer.Deserialize<Message>(response);
            if (String.IsNullOrWhiteSpace(msg.content)) throw new MessengerException("No messages from server.");
            RSA rsa = new RSA() { privateKey = key.key };
            string plaintext = rsa.DecryptMessage(msg.content);

            Console.WriteLine(plaintext);   // writes out the message
        }

        /// <summary>
        /// Reads a .key file and returns its JSON string.
        /// </summary>
        /// <param name="fileName">the file to read</param>
        /// <returns>the file as a JSON string, or null if it doesn't exist</returns>
        private string ReadKeyFromFile(string fileName)
        {
            string path = Path.Combine(currDir, fileName);
            string json_str;
            try
            {
                json_str = File.ReadAllText(path);
            }
            catch
            {
                // this means the key doesn't exist, so throw an error
                return null;    // null == error (the calling function should check if the return is null. 
                                // if it is, then print a message & kill the program)
            }
            return json_str;
        }

        /// <summary>
        /// Saves a key (as JSON) into a file.
        /// </summary>
        /// <param name="filename">the file name to save the data in</param>
        /// <param name="json">the key in JSON form</param>
        /// <returns>true/false whether or not the key was saved successfully</returns>
        private bool SaveKeyToFile(string filename, string json)
        {
            string path = Path.Combine(currDir, filename);
            try
            {
                File.WriteAllText(path, json);
            }
            catch 
            {
                return false; // error occurred
            }

            return true;
        }
    }

    /// <summary>
    /// A custom exception so that I don't have to catch the generic Exception class.
    /// </summary>
    class MessengerException : Exception
    {
        public MessengerException() { }

        public MessengerException(string message)
            : base (message) { }

        public MessengerException(string message, Exception inner)
            : base (message, inner) { }
    }
}

namespace ExtensionMethods
{

    /// <summary>
    /// Contains a couple extension methods for BigInteger.
    /// </summary>
    public static class MyExtensions
    {

        /// <summary>
        /// Calculates whether or not a given number is prime.
        /// </summary>
        /// <param name="value">the number to test</param>
        /// <param name="witnesses">the number of witnesses</param>
        /// <returns>true if the number is prime, else false</returns>
        public static Boolean IsProbablyPrime(this BigInteger value, int witnesses = 10)
        {
            if (value <= 1) return false;

            if (witnesses <= 0) witnesses = 10;

            BigInteger d = value - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            Byte[] bytes = new Byte[value.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < witnesses; i++)
            {
                do
                {
                    var Gen = new Random();
                    Gen.NextBytes(bytes);
                    a = new BigInteger(bytes);
                } while (a < 2 || a >= value - 2);

                BigInteger x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1) continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == 1) return false;
                    if (x == value - 1) break;
                }

                if (x != value - 1) return false;
            }
            return true;
        }

        /// <summary>
        /// Calculates the modular inverse of the given number mod another
        /// BigInteger.
        /// </summary>
        /// <param name="a">the dividend</param>
        /// <param name="n">the modulus</param>
        /// <returns>the modular inverse as a BigInteger</returns>
        public static BigInteger ModInverse(this BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - (t * x);
                v = x;
            }

            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }

    }
}
