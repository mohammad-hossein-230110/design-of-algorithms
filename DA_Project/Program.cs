using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.RegularExpressions;

namespace DATest
{
    internal class Program
    {

        #region Main

        static void Main()
        {
            string InputPath = Console.ReadLine();


            string[] BenignPaths = Directory.GetFiles("C:\\Users\\Mohamad hossein\\DA_Project\\Released1\\Released\\Train\\Benign");
            BenignPaths = BenignPaths.OrderBy(x => x.Substring(x.Length - 3, 3)).ToArray();

            string[] MalwareDirectories = Directory.GetDirectories("C:\\Users\\Mohamad hossein\\DA_Project\\Released1\\Released\\Train\\Malware Sample");
            MalwareDirectories = MalwareDirectories.OrderBy(x => x.Substring(x.Length - 2, 2)).ToArray();
            List<string[]> MalwareAX = new List<string[]>() { };
            (List<string>, List<string>) Lists = Utility(ref MalwareAX, MalwareDirectories, BenignPaths);

            int exit = int.MaxValue;
            while (exit != 0)
            {
                Console.WriteLine("Enter a number:");
                exit = int.Parse(Console.ReadLine());

                if (exit == 1)
                {
                    Pattern1(Lists.Item1, Lists.Item2, InputPath, InputPath);
                }
                else if (exit == 2)
                {
                    Pattern2(MalwareAX, InputPath, InputPath);
                }
                else if (exit == 3)
                {
                    Percent(InputPath, InputPath, MalwareAX);
                }

            }

        }
        #endregion

        #region Utilities

        public static string ReadFile(string Path)
        {
            FileStream fs = new FileStream(Path, FileMode.Open);

            StreamReader reader = new StreamReader(fs);
            string s = reader.ReadToEnd();
            return s;
        }

        public static List<string[]> ReturnMalwarepaths(string[] MalwareDirectories)
        {
            List<string[]> MalwarePaths = new List<string[]>();

            for (int i = 0; i < MalwareDirectories.Length; i++)
            {
                MalwarePaths.Add(Directory.GetFiles(MalwareDirectories[i]).OrderBy(x => x.Substring(x.Length - 4, 4)).ToArray());
            }
            return MalwarePaths;

        }

        public static (List<string>, List<string>) Utility(ref List<string[]> MalwareAX, string[] MalwareDirectories, string[] BenignPaths)
        {
            var watch = new System.Diagnostics.Stopwatch();
            watch.Start();
            List<string> BenignList = new List<string>();
            List<string> MalwareList = new List<string>();


            List<string[]> MalwarePaths = new List<string[]>();


            for (int i = 0; i < BenignPaths.Length; i++)
            {
                string str = ReadFile(BenignPaths[i]);
                BenignList.Add(str);


            }

            MalwarePaths = ReturnMalwarepaths(MalwareDirectories);

            //int sum = 0;
            for (int i = 0; i < MalwareDirectories.Length; i++)
            {
                string[] k = new string[MalwarePaths[i].Count()];

                for (int j = 0; j < MalwarePaths[i].Length; j++)
                {

                    string str = ReadFile(MalwarePaths[i][j]);
                    MalwareList.Add(str);
                    k[j] = str;
                    // sum++;

                }
                MalwareAX.Add(k);
            }


            // Console.WriteLine(sum);
            watch.Stop();
            Console.WriteLine(watch.ElapsedMilliseconds / 1000);

            return (BenignList, MalwareList);

        }


        public static List<(string, string)> GetInputs(string path)
        {

            string[] PathOfFiles = Directory.GetFiles(path);

            List<(string, string)> inputs = new List<(string, string)>();

            for (int a = 0; a < PathOfFiles.Length; a++)
            {
                inputs.Add((File.ReadAllText(PathOfFiles[a]), PathOfFiles[a]));
            }
            return inputs;

        }

        public static void AddToFolder(string Src, string DestinationDirectory)
        {
            //string dir = "C:\\Users\\Mohamad hossein\\TestFileDA";
            string dir = DestinationDirectory + "\\" + "Malwares";

            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            string Source = Src;
            string Destination = dir + "\\" + Path.GetFileName(Src);

            File.Move(Source, Destination);

        }

        static public int IsMatched(string Input, string Pattern)
        {
            int sum = 0;
            for (int k = 0; k < Math.Min(Pattern.Length, Input.Length); k++)
            {
                if (Input[k] == Pattern[k])
                {
                    sum++;
                }
                else return 0;
            }
            return sum;


        }
        public static int IsMatchedInLast(string Input, string Pattern)
        {
            if (Pattern.Length > Input.Length)
            {
                return 0;
            }

            int sum = 0;
            int inputlength = Input.Length;
            int patternlength = Pattern.Length;
            for (int k = Pattern.Length - 1; k >= 0; k--)
            {
                if (Input[inputlength - 1 + k - patternlength] == Pattern[k])
                {
                    sum++;
                }
                else return 0;
            }
            return sum;
        }

        #endregion

        #region Patterns = MalwareFiles

        public static void Pattern1(List<string> BenignList, List<string> MalwareList, string InputPath, string DestinationDirectory)
        {

            List<(string, string)> inputs = new List<(string, string)>();
            inputs = GetInputs(InputPath);

            List<string> Patterns = new List<string>();
            Patterns = MalwareList;



            for (int i = 0; i < Patterns.Count; i++)
            {
                for (int j = 0; j < inputs.Count; j++)
                {

                    if (IsMatched(inputs[j].Item1, Patterns[i]) == Math.Min(inputs[j].Item1.Length, Patterns[i].Length))
                    {
                        AddToFolder(inputs[j].Item2, DestinationDirectory);
                        inputs.RemoveAt(j);
                    }
                }
            }

            Console.WriteLine("Finsihed...");

            //Console.WriteLine("Number of Malware: " + sumMal);
            //Console.WriteLine("Number of Benigns: " + sumbeg);


        }
        #endregion

        #region Patterns = Longest Common Substring

        public static void Pattern2(List<string[]> MalwareAX, string InputPath, string DestinationDirectory)
        {
            List<(string, string)> inputs = new List<(string, string)>();
            inputs = GetInputs(InputPath);

            List<string> Patterns = new List<string>();

            Patterns = LCSPattern(MalwareAX);

            for (int i = 0; i < Patterns.Count; i++)
            {
                for (int j = 0; j < inputs.Count; j++)
                {

                    if (IsMatched(inputs[j].Item1, Patterns[i]) == Math.Min(Patterns[i].Length, inputs[j].Item1.Length))
                    {
                        AddToFolder(inputs[j].Item2, DestinationDirectory);
                        inputs.RemoveAt(j);
                    }
                }
            }

            Console.WriteLine("Finsihed...");
        }

        static public string FindLongestCommonSubstring(string str1, string str2)
        {
            int[,] lengths = new int[str1.Length + 1, str2.Length + 1];
            int maxLength = 0;
            int maxI = 0;
            int maxJ = 0;

            for (int i = 0; i <= str1.Length; i++)
            {
                for (int j = 0; j <= str2.Length; j++)
                {
                    if (i == 0 || j == 0)
                    {
                        lengths[i, j] = 0;
                    }
                    else if (str1[i - 1] == str2[j - 1])
                    {
                        lengths[i, j] = lengths[i - 1, j - 1] + 1;
                        if (lengths[i, j] > maxLength)
                        {
                            maxLength = lengths[i, j];
                            maxI = i;
                            maxJ = j;
                        }
                    }
                    else
                    {
                        lengths[i, j] = 0;
                    }
                }
            }

            string longestSubstring = "";

            while (maxLength > 0)
            {
                longestSubstring = str1[maxI - 1] + longestSubstring;
                maxLength--;
                maxI--;
                maxJ--;
            }

            return longestSubstring;
        }

        static public List<string> LCSPattern(List<string[]> MalwareAX)
        {


            List<string> Patterns = new List<string>();

            int divide = 5;

            for (int i = 0; i < MalwareAX.Count; i++)
            {
                for (int j = 0; j < divide; j++)
                {

                    string str1 = MalwareAX[i][j * (MalwareAX[i].Length / divide) + 0];
                    string str2 = MalwareAX[i][j * (MalwareAX[i].Length / divide) + 1];
                    string lcs = "";
                    if (str1.Length < 500000 && str2.Length < 500000)
                    {
                        lcs = FindLongestCommonSubstring(str1.Substring(0, str1.Length / 200), str2.Substring(0, str2.Length / 200));
                        Patterns.Add(lcs);
                    }
                    else if (str1.Length < 100000 && str2.Length < 100000 && str1.Length > 5000 && str2.Length > 5000)
                    {
                        lcs = FindLongestCommonSubstring(str1.Substring(0, 500), str2.Substring(0, 500));
                        Patterns.Add(lcs);
                    }
                    else if (str1.Length < 5000 && str2.Length < 5000)
                    {
                        lcs = FindLongestCommonSubstring(str1, str2);
                        Patterns.Add(lcs);
                    }


                }

            }

            return Patterns;
        }

        #endregion  

        #region Patterns = A few percent of first and last

        public static void Percent(string InputPath, string DestinationDirectory, List<string[]> MalwareAX)
        {
            List<(string, string)> inputs = new List<(string, string)>();
            inputs = GetInputs(InputPath);

            List<string> Patterns = new List<string>();

            Patterns = LastFewPercent(MalwareAX).Concat(FirstFewPercent(MalwareAX)).ToList();


            for (int i = 0; i < Patterns.Count; i++)
            {
                for (int j = 0; j < inputs.Count; j++)
                {

                    if (IsMatchedInLast(inputs[j].Item1, Patterns[i]) == Math.Min(Patterns[i].Length, inputs[j].Item1.Length) ||
                        IsMatched(inputs[j].Item1, Patterns[i]) == Math.Min(Patterns[i].Length, inputs[j].Item1.Length))

                    {
                        AddToFolder(inputs[j].Item2, DestinationDirectory);
                        inputs.RemoveAt(j);
                    }


                }
            }

            Console.WriteLine("Finsihed...");
        }

        public static List<string> LastFewPercent(List<string[]> MalwareAX)
        {

            int number = 3;
            int percent = 5;
            List<string> Patterns = new List<string>();

            for (int i = 0; i < MalwareAX.Count; i++)
            {
                for (int j = 0; j < number; j++)
                {
                    int end = MalwareAX[i].Length - 1 - j;
                    string str1 = MalwareAX[i][j].Substring((MalwareAX[i][j].Length * (100 - percent)) / 100, MalwareAX[i][j].Length - 1 - ((MalwareAX[i][j].Length * (100 - percent)) / 100));
                    string str2 = MalwareAX[i][end].Substring((MalwareAX[i][end].Length * (100 - percent)) / 100, MalwareAX[i][end].Length - 1 - ((MalwareAX[i][end].Length * (100 - percent)) / 100));
                    Patterns.Add(str1);
                    Patterns.Add(str2);
                }
            }

            return Patterns;
        }
        public static List<string> FirstFewPercent(List<string[]> MalwareAX)
        {

            int number = 3;
            int percent = 5;
            List<string> Patterns = new List<string>();

            for (int i = 0; i < MalwareAX.Count; i++)
            {
                for (int j = 0; j < number; j++)
                {
                    int end = MalwareAX[i].Length - 1 - j;
                    string str1 = MalwareAX[i][j].Substring(0, (MalwareAX[i][j].Length * (percent)) / 100);
                    string str2 = MalwareAX[i][end].Substring(0, (MalwareAX[i][end].Length * (percent)) / 100);
                    Patterns.Add(str1);
                    Patterns.Add(str2);
                }
            }

            return Patterns;
        }

    }
    #endregion


}