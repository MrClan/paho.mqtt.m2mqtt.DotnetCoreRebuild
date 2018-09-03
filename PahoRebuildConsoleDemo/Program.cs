using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using uPLibrary.Networking.M2Mqtt;
using uPLibrary.Networking.M2Mqtt.Messages;

namespace PahoRebuildConsoleDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            Init();
            Console.ReadLine();
        }

        const string MQTT_BROKER_ADDRESS = "192.168.1.3";
        const int DEFAULT_SSL_PORT = 8883;
        const string username = "mqttusername";
        const string password = "mqttpassword";

        static void Init()
        {
            var rootCertPath = @"pathToRootCertificate";
            if (!System.IO.File.Exists(rootCertPath)) throw new Exception("RootCertificate file not found");
            X509Certificate2 root = new X509Certificate2(rootCertPath);
            var intermediateCertPath = @"pathToIntermediateCertificate";
            if (!System.IO.File.Exists(intermediateCertPath)) throw new Exception("Intermediate Certificate file not found");
            X509Certificate2 intermediate = new X509Certificate2(intermediateCertPath);

            var x509Store = new X509Store(StoreLocation.CurrentUser);
            x509Store.Open(OpenFlags.ReadWrite);
            x509Store.Add(root);
            x509Store.Add(intermediate);
            x509Store.Close();


            RemoteCertificateValidationCallback callback = (sender, certificate, chain, errors) => VerifyCert(certificate, new[] { root, intermediate});

            // create client instance 
            MqttClient client = new MqttClient(MQTT_BROKER_ADDRESS, DEFAULT_SSL_PORT, true, root, intermediate, MqttSslProtocols.TLSv1_2, callback);

            // register to message received 
            client.MqttMsgPublishReceived += client_MqttMsgPublishReceived;

            string clientId = Guid.NewGuid().ToString();
            client.Connect(clientId, username, password);

            // subscribe to the topic "/home/temperature" with QoS 2 
            client.Subscribe(new string[] { "public/#" }, new byte[] { MqttMsgBase.QOS_LEVEL_AT_LEAST_ONCE });
            Console.ReadLine();
        }

        static void client_MqttMsgPublishReceived(object sender, MqttMsgPublishEventArgs e)
        {
            // handle message received 
            Console.WriteLine(Encoding.UTF8.GetString(e.Message));
        }

        private static bool VerifyCert(X509Certificate primary, X509Certificate2[] additional)
        {
            var chain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    VerificationFlags = X509VerificationFlags.IgnoreWrongUsage | X509VerificationFlags.AllowUnknownCertificateAuthority
                }
            };

            chain.ChainPolicy.ExtraStore.AddRange(additional);

            // Do the preliminary validation.
            try
            {
                if (!chain.Build(new X509Certificate2(primary)))
                {
                    return false;
                }
            }
            catch (Exception exception)
            {
                
            }

            // Make sure we have the same number of elements.
            if (chain.ChainElements.Count != chain.ChainPolicy.ExtraStore.Count + 1)
            {
                return false;
            }

            // Make sure all the thumbprints of the CAs match up.
            // The first one should be 'primaryCert', leading up to the root CA.
            for (var i = 1; i < chain.ChainElements.Count; i++)
            {
                if (chain.ChainElements[i].Certificate.Thumbprint != chain.ChainPolicy.ExtraStore[i - 1].Thumbprint)
                {
                    return false;
                }
            }

            return true;
        }
    }
}

