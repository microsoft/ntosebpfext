// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

using Microsoft.Extensions.Logging;

namespace process_monitor.Library
{
    public sealed class ProcessMonitor : IDisposable
    {
        private readonly ILogger<ProcessMonitor> _logger;
        private bool disposedValue;

        public ProcessMonitor(ILogger<ProcessMonitor> logger)
        {
            _logger = logger;
            ProcessMonitorBPFLoader.Subscribe(this, logger);
        }

        public event EventHandler<ProcessCreatedEventArgs>? ProcessCreated;
        public event EventHandler<ProcessDestroyedEventArgs>? ProcessDestroyed;

        internal void RaiseProcessCreated(in ProcessCreatedEventArgs e)
        {
            _logger.LogDebug("Process created: PID:{pid}, Image:{imageFileName}, CommandLine:{commandLine}, ParentPID:{parentPid}, Create Time:{createTime}",
                e.ProcessId, e.ImageFileName, e.CommandLine, e.ParentProcessId, e.CreateTime);

            try
            {
                ProcessCreated?.Invoke(this, e);
            }
            catch (Exception) { } // Prevent exceptions from bubbling back up to the native code
        }

        internal void RaiseProcessDestroyed(in ProcessDestroyedEventArgs e)
        {
            _logger.LogDebug("Process destroyed: PID:{pid}, Image:{imageFileName}, CommandLine:{commandLine}, Exit Time:{exitTime}, Exit Code:{exitCode}",
                e.ProcessId, e.ImageFileName, e.CommandLine, e.ExitTime, e.ExitCode);

            try
            {
                ProcessDestroyed?.Invoke(this, e);
            }
            catch (Exception) { } // Prevent exceptions from bubbling back up to the native code)
        }

        #region IDisposable Support

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // Dispose managed state (managed objects).  There are none currently.
                }

                ProcessMonitorBPFLoader.Unsubscribe(this);
                disposedValue = true;
            }
        }

        ~ProcessMonitor()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
