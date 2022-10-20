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
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Reflection;
using MigrationBase;

namespace SmartMove
{
    /// <summary>
    /// Interaction logic for AboutWindow.xaml
    /// </summary>
    public partial class AboutWindow : Window
    {
        #region Construction

        public AboutWindow(Vendor vendor)
        {
            InitializeComponent();

            AssemblyVersion = "Version " + Assembly.GetExecutingAssembly().GetName().Version;

            switch (vendor)
            {
                case Vendor.CiscoASA:
                    AssemblyProduct = SupportedVendors.CiscoProduct;
                    AssemblyDescription = SupportedVendors.CiscoProductDescription;
                    break;
                case Vendor.JuniperJunosOS:
                    AssemblyProduct = SupportedVendors.JuniperProduct;
                    AssemblyDescription = SupportedVendors.JuniperProductDescription;
                    break;
                case Vendor.JuniperScreenOS:
                    AssemblyProduct = SupportedVendors.NetScreenProduct;
                    AssemblyDescription = SupportedVendors.NetScreenProductDescription;
                    break;
                case Vendor.FortiGate:
                    AssemblyProduct = SupportedVendors.FortiGateProduct;
                    AssemblyDescription = SupportedVendors.FortiGateProductDescription;
                    break;
            }

            object[] attributes = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyCopyrightAttribute), false);
            AssemblyCopyright = (attributes.Length == 0) ? "" : ((AssemblyCopyrightAttribute)attributes[0]).Copyright;

            attributes = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyCompanyAttribute), false);
            AssemblyCompany = (attributes.Length == 0) ? "" : ((AssemblyCompanyAttribute)attributes[0]).Company;

            SKTextDisplay.Text = MainWindow.SKText;
            SKLinkDisplay.Text = MainWindow.SKLinkText;
            SKLinkDisplay.Tag = MainWindow.SKLinkAddress;

            if (File.Exists("about.html"))
            {
                CustomLogoDisplayer.Navigate(new Uri(String.Format("file:///{0}/about.html", Directory.GetCurrentDirectory())));
                CustomLogoPanel.Visibility = Visibility.Visible;
            }

            Loaded += OnLoaded;
            Unloaded += OnUnloaded;
        }

        #endregion

        #region Properties

        #region AssemblyProduct

        public string AssemblyProduct
        {
            get { return (string)GetValue(AssemblyProductProperty); }
            set { SetValue(AssemblyProductProperty, value); }
        }

        public static readonly DependencyProperty AssemblyProductProperty =
            DependencyProperty.Register("AssemblyProduct", typeof(string), typeof(AboutWindow), new PropertyMetadata(null));

        #endregion

        #region AssemblyVersion

        public string AssemblyVersion
        {
            get { return (string)GetValue(AssemblyVersionProperty); }
            set { SetValue(AssemblyVersionProperty, value); }
        }

        public static readonly DependencyProperty AssemblyVersionProperty =
            DependencyProperty.Register("AssemblyVersion", typeof(string), typeof(AboutWindow), new PropertyMetadata(null));

        #endregion

        #region AssemblyCopyright

        public string AssemblyCopyright
        {
            get { return (string)GetValue(AssemblyCopyrightProperty); }
            set { SetValue(AssemblyCopyrightProperty, value); }
        }

        public static readonly DependencyProperty AssemblyCopyrightProperty =
            DependencyProperty.Register("AssemblyCopyright", typeof(string), typeof(AboutWindow), new PropertyMetadata(null));

        #endregion

        #region AssemblyCompany

        public string AssemblyCompany
        {
            get { return (string)GetValue(AssemblyCompanyProperty); }
            set { SetValue(AssemblyCompanyProperty, value); }
        }

        public static readonly DependencyProperty AssemblyCompanyProperty =
            DependencyProperty.Register("AssemblyCompany", typeof(string), typeof(AboutWindow), new PropertyMetadata(null));

        #endregion

        #region AssemblyDescription

        public string AssemblyDescription
        {
            get { return (string)GetValue(AssemblyDescriptionProperty); }
            set { SetValue(AssemblyDescriptionProperty, value); }
        }

        public static readonly DependencyProperty AssemblyDescriptionProperty =
            DependencyProperty.Register("AssemblyDescription", typeof(string), typeof(AboutWindow), new PropertyMetadata(null));

        #endregion

        #endregion

        #region Event Handlers

        private void OnLoaded(object sender, RoutedEventArgs routedEventArgs)
        {
            Ok.Focus();
        }

        private void OnUnloaded(object sender, RoutedEventArgs routedEventArgs)
        {
            CustomLogoDisplayer.Dispose();
            CustomLogoDisplayer = null;
        }

        private void CloseButton_OnClick(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void HeaderPanel_OnMouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left && e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        private void Link_OnClick(object sender, MouseButtonEventArgs e)
        {
            var link = (TextBlock)sender;
            if (link != null)
            {
                var psi = new ProcessStartInfo(link.Tag.ToString()) { UseShellExecute = true };
                Process.Start(psi);
            }
        }

        #endregion
    }
}
