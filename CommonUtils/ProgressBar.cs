using System;
using System.IO;
using System.Text;
using System.Threading;

namespace CommonUtils
{
    public class ProgressBar : IDisposable
    {
        public float CurrentProgress => writer.CurrentProgress;

        private TextWriter OriginalWriter;
        private ProgressWriter writer;

        public ProgressBar()
        {
            OriginalWriter = Console.Out;
            writer = new ProgressWriter(OriginalWriter);
            Console.SetOut(writer);
        }

        public void Dispose()
        {
            Console.SetOut(OriginalWriter);
            writer.ClearProgressBar();
        }

        public void SetProgress(float f)
        {
            writer.CurrentProgress = f;
            writer.RedrawProgress();
        }
        public void SetProgress(int i)
        {
            SetProgress((float)i);
        }

        public void Increment(float f)
        {
            writer.CurrentProgress += f;
            writer.RedrawProgress();
        }

        public void Increment(int i)
        {
            Increment((float)i);
        }

        private class ProgressWriter : TextWriter
        {

            public override Encoding Encoding => Encoding.UTF8;
            public float CurrentProgress
            {
                get { return _currentProgress; }
                set
                {
                    _currentProgress = value;
                    if (_currentProgress > 100)
                    {
                        _currentProgress = 100;
                    }
                    else if (CurrentProgress < 0)
                    {
                        _currentProgress = 0;
                    }
                }
            }

            private float _currentProgress = 0;
            private TextWriter consoleOut;
            private const string ProgressTemplate = "[{0}] {1:n2}%";
            private const int AllocatedTemplateSpace = 11;
            private object SyncLock = new object();
            public ProgressWriter(TextWriter _consoleOut)
            {
                consoleOut = _consoleOut;
                RedrawProgress();
            }

            private void DrawProgressBar()
            {
                lock (SyncLock)
                {
                    int avalibleSpace = Console.BufferWidth - AllocatedTemplateSpace;
                    int percentAmmount = (int)((float)avalibleSpace * (CurrentProgress / 100));
                    var col = Console.ForegroundColor;
                    Console.ForegroundColor = ConsoleColor.White;
                    string progressBar = string.Concat(new string('=', percentAmmount), new string(' ', avalibleSpace - percentAmmount));
                    consoleOut.Write(string.Format(ProgressTemplate, progressBar, CurrentProgress));
                    Console.ForegroundColor = col;
                }
            }

            public void RedrawProgress()
            {
                lock (SyncLock)
                {
                    int LastLineWidth = Console.CursorLeft;
                    var consoleH = Console.WindowTop + Console.WindowHeight - 1;
                    Console.SetCursorPosition(0, consoleH);
                    DrawProgressBar();
                    Console.SetCursorPosition(LastLineWidth, consoleH - 1);
                }
            }

            private void ClearLineEnd()
            {
                lock (SyncLock)
                {
                    int lineEndClear = Console.BufferWidth - Console.CursorLeft - 1;
                    consoleOut.Write(new string(' ', lineEndClear));
                }
            }

            public void ClearProgressBar()
            {
                lock (SyncLock)
                {
                    int LastLineWidth = Console.CursorLeft;
                    var consoleH = Console.WindowTop + Console.WindowHeight - 1;
                    Console.SetCursorPosition(0, consoleH);
                    ClearLineEnd();
                    Console.SetCursorPosition(LastLineWidth, consoleH);
                }
            }

            public override void Write(char value)
            {
                lock (SyncLock)
                {
                    consoleOut.Write(value);
                }
            }

            public override void Write(string value)
            {
                lock (SyncLock)
                {
                    consoleOut.Write(value);
                }
            }

            public override void WriteLine(string value)
            {
                lock (SyncLock)
                {
                    consoleOut.Write(value);
                    consoleOut.Write(Environment.NewLine);
                    ClearLineEnd();
                    consoleOut.Write(Environment.NewLine);
                    RedrawProgress();
                }
            }

            public override void WriteLine(string format, params object[] arg)
            {
                WriteLine(string.Format(format, arg));
            }

            public override void WriteLine(int i)
            {
                WriteLine(i.ToString());
            }

        }
    }
}
