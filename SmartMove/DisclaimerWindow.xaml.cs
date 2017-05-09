/********************************************************************
Copyright (c) 2017, Check Point Software Technologies Ltd.
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
********************************************************************/

using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;

namespace SmartMove
{
    /// <summary>
    /// Interaction logic for DisclaimerWindow.xaml
    /// </summary>
    public partial class DisclaimerWindow : Window
    {
        #region Constants

        private const string DisclaimerFileName = "SmartMove Tool Legal.rtf";
        
        #endregion

        #region Construction

        public DisclaimerWindow()
        {
            InitializeComponent();
            Loaded += OnLoaded;
        }
        
        #endregion

        #region Event Handlers

        private void OnLoaded(object sender, RoutedEventArgs routedEventArgs)
        {
            if (!File.Exists(DisclaimerFileName))
            {
                MainWindow.ShowMessage("Product legal document is missing.\nCannot run the tool.", MessageTypes.Error);
                Close();
            }
            else
            {
                try
                {
                    var fs = new FileStream(DisclaimerFileName, FileMode.Open, FileAccess.Read);
                    var disclaimerText = new TextRange(DisclaimerText.Document.ContentStart, DisclaimerText.Document.ContentEnd);

                    disclaimerText.Load(fs, DataFormats.Rtf);
                    AcceptDisclaimer.Focus();
                }
                catch (Exception ex)
                {
                    MainWindow.ShowMessage("Failed to load Product legal document.\nCannot run the tool.", MessageTypes.Error);
                    Close();
                }
            }
        }

        private void CloseButton_OnClick(object sender, RoutedEventArgs e)
        {
            var button = (Button)sender;
            DialogResult = !button.IsCancel;
        }

        private void HeaderPanel_OnMouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left && e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }
        
        #endregion
    }
}
