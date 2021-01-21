use indy_api_types::{ErrorCode, CommandHandle};
//use crate::commands::{Command, CommandExecutor};
//use crate::commands::metrics::MetricsCommand;
use indy_utils::ctypes;
use libc::c_char;
use std::ffi::CString;

/// Collect metrics.
///
/// #Returns
/// Map in the JSON format. Where keys are names of metrics.
///
/// #Errors
/// Common*
#[no_mangle]
pub extern fn indy_collect_metrics(command_handle: CommandHandle,
                                   cb: Option<extern fn(command_handle_: CommandHandle,
                                                        err: ErrorCode,
                                                        metrics_json: *const c_char)>) -> ErrorCode {
    trace!("indy_collect_metrics: >>> command_handle: {:?}, cb: {:?}",
           command_handle, cb);

    check_useful_c_callback!(cb, ErrorCode::CommonInvalidParam3);

    cb(command_handle, ErrorCode::Success, CString::new("").unwrap().as_ptr());

    let res = ErrorCode::Success;
    trace!("indy_collect_metrics: <<< res: {:?}", res);
    res
}
