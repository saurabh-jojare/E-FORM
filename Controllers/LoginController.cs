using EFORM.DAL;
using EFORM.Extensions;
using EFORM.Models;
using EntityFramework.Audit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace EFORM.Controllers
{
    [HandleError]
    public class LoginController : Controller
    {
        [HttpGet]
        public ActionResult Login()   // Login
        {
            if (PMGSYSession.Current.UserName != null)
            {
                Session.Abandon();
                regenerateId();
                Response.Redirect("/Login/Login/");
            }

            LoginModel model = new LoginModel();//Added By Abhishek kamble 24-Apr-2014
            model.ValidateCaptcha = false;
            return View(model);
          
        }

        [AllowAnonymous]
        [HttpPost]
        public JsonResult GetSessionSalt(string id)
        
        {
            try
            {
                //Request.Cookies["ASP.NET_SessionId"].Secure = true;
                regenerateId();
                //generate a random number
                //added by PP[07-05-2018]
                Random ran = new Random();
                Int64 i64 = ran.Next(10000000, 99999999);
                i64 = (i64 * 100000000) + ran.Next(0, 999999999);
                var v16 = Math.Abs(i64);
                Session["SessionSalt"] = v16;
                PMGSYSession.Current.SessionSalt = Convert.ToInt64(Session["SessionSalt"]);
                //end
                #region OLD LOGIC
                //Session["SessionSalt"] = new Random().Next(9999, 9999999);
                //PMGSYSession.Current.SessionSalt = Convert.ToInt32(Session["SessionSalt"]);
                //return new JsonResult { Data = PMGSYSession.Current.SessionSalt }; 
                #endregion
                return new JsonResult { Data = PMGSYSession.Current.SessionSalt };
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                return null;
            }
        }


        [HttpPost]
        [AllowAnonymous]
        public ActionResult Login(string id, LoginModel model)
        {
            UserAuthModel userAuthModel = new UserAuthModel();
            EformEntities dbContext = new EformEntities();
            Login login = new Login();    //Login.cs 

            try
            {
                //Added By Abhishek kamble to check user failed attempts start 24-Apr-2014
                if ((model.ValidateCaptcha == false) || (model.ValidateCaptcha == null))
                {
                    if (ModelState.ContainsKey("Captcha"))
                    {
                        ModelState["Captcha"].Errors.Clear();
                    }
                }


                if (ModelState.IsValid)
                {
                    if (PMGSYSession.Current.SessionSalt == 0)
                    {
                        Response.Cache.SetCacheability(HttpCacheability.NoCache);
                        Response.Cache.SetExpires(DateTime.UtcNow.AddHours(-1));
                        Response.Cache.SetNoServerCaching();
                        Response.Cache.SetNoStore();
                        return Redirect("/Login/SessionExpire");
                    }

                    if (!Session["ASP.NET_SessionId"].ToString().Equals(Request.Cookies["ASP.NET_SessionId"].Value))
                    {
                        throw new Exception("invalid session");
                    }

                    userAuthModel = login.AuthenticateUser(model);


                    //Added By Abhishek kamble 25-Apr-2014 To check is Captcha Required  start   
                    if (userAuthModel.isCaptchaRequired == true)
                    {
                        model.ShowCaptcha = true;
                        model.ValidateCaptcha = true;
                    }
                    else
                    {
                        model.ShowCaptcha = false;
                        model.ValidateCaptcha = false;
                    }

                    if (!userAuthModel.Message.Equals(string.Empty))
                    {
                        ModelState.AddModelError("", userAuthModel.Message);
                        return View(model);
                    }
                    //Added By Abhishek kamble 25-Apr-2014 To check is Captcha Required  end   

                    // Set Number of users
                    HttpContext.Application.Lock();
                    HttpContext.Application["OnlineUsers"] = Convert.ToInt32(HttpContext.Application["OnlineUsers"]) + 1;
                    HttpContext.Application.UnLock();

                    //set cookie for admin user to allow access to elmah.axd
                    FormsAuthentication.SetAuthCookie(PMGSYSession.Current.UserName, true);
                    if (userAuthModel.IsFirstLogin)
                    {
                        //redirect to Change Password Page
                        ChangePasswordModel chpModel = new ChangePasswordModel();
                        chpModel.UserId = PMGSYSession.Current.UserId;

                        chpModel.RoleId = PMGSYSession.Current.RoleCode;
                        chpModel.UserName = PMGSYSession.Current.UserName;


                        //if Already entered password question & answer
                        var PwdrQuesId = (from uup in dbContext.UM_Security_Question_Answer
                                          where uup.UserID == PMGSYSession.Current.UserId
                                          select uup.PasswordQuestionID).FirstOrDefault();
                        if (PwdrQuesId != 0)
                        {
                            chpModel.PwdrQuestionId = PwdrQuesId;
                            chpModel.PwdrAnswer = dbContext.UM_Security_Question_Answer.Where(c => c.PasswordQuestionID == PwdrQuesId && c.UserID == PMGSYSession.Current.UserId).Select(c => c.Answer).FirstOrDefault();
                        }

                        chpModel.QuestionList = new Login().GetPwdrQuestionList();
                        return RedirectToAction("ChangePassword", chpModel);
                    }
                    else
                    {
                        //For SRRDA Login as a PIU
                        if (PMGSYSession.Current.LevelId == 4 && (PMGSYSession.Current.RoleCode == 22 || PMGSYSession.Current.RoleCode == 38 || PMGSYSession.Current.RoleCode == 54))
                        {
                            return RedirectToAction("StateAsPIU");
                        }
                        else
                        {
                            return RedirectToHome();
                        }
                    }
                }
                else
                {
                    //Added By Abhishek kamble 24-Apr-2014
                    GetCaptchaImages();
                    if (model.ValidateCaptcha == true)
                    {
                        model.ShowCaptcha = true;
                    }

                    if (!string.IsNullOrEmpty(model.UserName) && !string.IsNullOrEmpty(model.Password))
                    {
                        // If we got this far, something failed, redisplay form
                        //Commented By Abhishek kamble 24-Apr-2014

                        //ModelState.AddModelError("", "The user name or password provided is incorrect.");                                                   
                    }
                    else
                    {
                        return View(model);
                    }
                }

                return View(model);
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                ModelState.AddModelError("", "Error occurred while login. Please try again.");
                return View(model);
            }
            finally
            {

                dbContext.Dispose();
            }
        }

        [Audit]
        //[RequiredAuthentication]
        public ActionResult RecoverPwdrQuestion()
        {
            List<SelectListItem> questionList = new List<SelectListItem>();
            questionList = new Login().GetPwdrQuestionList();
            ViewBag.QuestionList = questionList;
            return View("RecoverPwdrQuestion");
        }





        public ActionResult UserLoginAttemptStatus(string UserName)
        {
            var dbContext = new EformEntities();
            string doubleEncPwdr = string.Empty;
            Login login = new Login();

            try
            {

                UM_User_Master userMasterModel = (from u in dbContext.UM_User_Master
                                                  where u.UserName.Equals(UserName.Trim())
                                                  select u).FirstOrDefault();
                if (userMasterModel == null)
                {
                    return Json(new { ShowCaptch = false }, JsonRequestBehavior.AllowGet);
                }
                else
                {
                    if (userMasterModel.FailedPasswordAttempts >= Convert.ToInt32(System.Configuration.ConfigurationManager.AppSettings["WrongPasswordAllowdCount"].ToString()))
                    {
                        return Json(new { ShowCaptch = true }, JsonRequestBehavior.AllowGet);
                    }
                    else
                    {
                        return Json(new { ShowCaptch = false }, JsonRequestBehavior.AllowGet);
                    }
                }
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                return Json(new { ShowCaptch = false }, JsonRequestBehavior.AllowGet);
            }
            finally
            {
                if (dbContext != null)
                {
                    dbContext.Dispose();
                }
            }
        }


        [HttpGet]
        [Audit]
        [RequiredAuthentication]
        public ActionResult ChangePassword()
        {
            var dbContext = new EformEntities();
            try
            {
                ChangePasswordModel model = new ChangePasswordModel();
                model.UserId = PMGSYSession.Current.UserId;
                model.UserName = PMGSYSession.Current.UserName;
                model.RoleId = PMGSYSession.Current.RoleCode;

                //if Already entered password question & answer
                var PwdrQuesId = (from uup in dbContext.UM_Security_Question_Answer
                                  where uup.UserID == PMGSYSession.Current.UserId
                                  select uup.PasswordQuestionID).FirstOrDefault();
                if (PwdrQuesId != 0)
                {
                    model.PwdrQuestionId = PwdrQuesId;
                    model.PwdrAnswer = dbContext.UM_Security_Question_Answer.Where(c => c.PasswordQuestionID == PwdrQuesId && c.UserID == PMGSYSession.Current.UserId).Select(c => c.Answer).FirstOrDefault();
                }

                model.QuestionList = new Login().GetPwdrQuestionList();

                return View(model);
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                return View("Error");
            }
            finally
            {
                dbContext.Dispose();
            }
        }

        [HttpGet]
        public ActionResult SessionExpire()
        {
            return View();
        }

        [HttpGet]
        public ActionResult Error(string id)
        {
            return View();
        }


        /// <summary>
        /// Method for checking valid roles
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Audit]
        public ActionResult UnAuthorized()
        {
            return View();
        }


        [RequiredAuthentication]
        public ActionResult ValidateRoles(string id)
        {
            try
            {
                LoginRoleModel loginModel = new LoginRoleModel();
                loginModel.RoleList = new Login().GetUserRoleList(id);
                return PartialView("_LoginRolePartial", loginModel);
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                return Redirect("/Login/SessionExpire");
            }
        }



        [HttpGet]
        [Audit]
        //[OutputCache(NoStore = true, Duration = 0, VaryByParam = "*")]
        public ActionResult Logout()
        {

            try
            {
                bool IsUpdateSuccess = new Login().UpdateLogDetails();
                if (IsUpdateSuccess)
                    PMGSYSession.Current.EndSession();

                Response.Cache.SetCacheability(HttpCacheability.NoCache);
                Response.Cache.SetExpires(DateTime.UtcNow.AddHours(-1));
                //Response.Cache.SetNoServerCaching();
                Response.Cache.SetNoStore();
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                PMGSYSession.Current.EndSession();
                Response.Cache.SetCacheability(HttpCacheability.NoCache);
                Response.Cache.SetExpires(DateTime.UtcNow.AddHours(-1));
                //Response.Cache.SetNoServerCaching();
                Response.Cache.SetNoStore();
                return RedirectToAction("Login");
            }
        }


        [HttpPost]
        [Audit]
        [ValidateAntiForgeryToken]
        public ActionResult RecoverPwdrQuestion(RecoverPwdrQuestionModel model)
        {
            UserAuthModel userAuthModel = new UserAuthModel();

            try
            {
                model.PwdrAnswer = DecryptAes(model.PwdrAnswer);//added by PP[08-05-2018]

                if (ModelState.IsValid)
                {
                    if (model.PwdrAnswer.Trim().Equals(""))
                    {
                        // 10.8 User Enumeration (OTG-IDENT-004), (OTG-IDENT-005) 
                        ModelState.AddModelError("", "Invalid details are entered.");
                        // ModelState.AddModelError("", "Invalid Answer.");
                        return RecoverPwdrQuestion();
                    }

                    userAuthModel = new Login().GetPwdrQuestionAnsDetails(model);

                    if (!userAuthModel.IsQuestionSelected)
                    {
                        // 10.8 User Enumeration (OTG-IDENT-004), (OTG-IDENT-005) 
                        ModelState.AddModelError("", "Invalid details are entered.");
                        // ModelState.AddModelError("", "Please select question.");
                        return RecoverPwdrQuestion();
                    }

                    if (!userAuthModel.IsUserExist)
                    {
                        //  ModelState.AddModelError("", "User not exist."); // Change is made on 08 DEC 2020. As per suggestion in Security Mail dated 07 DEC 2020 by Anita Mam to Rohit.
                        // 10.8 User Enumeration (OTG-IDENT-004), (OTG-IDENT-005) 
                        ModelState.AddModelError("", "Invalid details are entered.");
                        return RecoverPwdrQuestion();
                    }

                    if (userAuthModel.IsPwdrQuestionWrong)
                    {
                        // 10.8 User Enumeration (OTG-IDENT-004), (OTG-IDENT-005) 
                        ModelState.AddModelError("", "Invalid details are entered.");
                        // ModelState.AddModelError("", "Selected Question is wrong.");
                        return RecoverPwdrQuestion();
                    }

                    if (userAuthModel.IsPwdrAnswerWrong)
                    {
                        // 10.8 User Enumeration (OTG-IDENT-004), (OTG-IDENT-005) 
                        ModelState.AddModelError("", "Invalid details are entered.");
                        // ModelState.AddModelError("", "Provided Answer is wrong.");
                        return RecoverPwdrQuestion();
                    }

                    RecoverPasswordModel rpModel = new RecoverPasswordModel();
                    rpModel.UserId = userAuthModel.UserId;
                    rpModel.UserName = userAuthModel.UserName;
                    //rpModel.RoleId = userAuthModel.RoleId;
                    return View("RecoverPassword", rpModel);
                }
                else
                {
                    //Added By Abhishek kamble 25-Apr-2014
                    GetCaptchaImages();
                    return RecoverPwdrQuestion();
                }
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                return View("Error");
            }
        }


        [HttpGet]
        [Audit]
        [RequiredAuthentication]
        public ActionResult RecoverPassword(UserMasterModel umModel, string id = "0")
        {
            RecoverPasswordModel model = new RecoverPasswordModel();
            model.UserId = umModel.UserId;
            model.UserName = umModel.UserName;
            return View("RecoverPassword", model);
        }


        [HttpPost]
        [Audit]
        [ValidateAntiForgeryToken]
        public ActionResult RecoverPassword(RecoverPasswordModel model)
        {
            //Put Try Catch
            UserAuthModel userAuthModel = new UserAuthModel();
            try
            {
                if (ModelState.IsValid)
                {
                    if (model.NewPassword.ToUpper().Equals((new Login().EncodePassword(model.UserName)).ToUpper()))
                    {
                        return Json(new { Success = false, ErrorMessage = "Password should not be same as User name." });
                    }

                    userAuthModel = new Login().UpdatePassword(model);

                    if (userAuthModel.IsOldAndNewPwdrSame)
                    {
                        return Json(new { Success = false, ErrorMessage = "New password should not be same as Old password." });
                    }

                    ModelState.Clear();
                    return Json(new { Success = true });
                }
                else
                {
                    StringBuilder errorMessages = new StringBuilder();
                    foreach (var modelStateValue in ModelState.Values)
                    {
                        foreach (var error in modelStateValue.Errors)
                        {
                            errorMessages.Append(error.ErrorMessage);
                        }
                    }
                    return Json(new { Success = false, ErrorMessage = errorMessages.ToString() });
                }
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                return Json(new { Success = false, ErrorMessage = "Error occurred while changing the new password." });
            }
        }



        public String DecryptAes(String encryptedString)
        {

            var cipherText = Convert.FromBase64String(encryptedString);
            var key = Encoding.UTF8.GetBytes("7061737323313233");
            var iv = Encoding.UTF8.GetBytes("7061737323313233");

            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (var rijAlg = new RijndaelManaged())
            {
                //Settings
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.FeedbackSize = 128;

                rijAlg.Key = key;
                rijAlg.IV = iv;

                // Create a decrytor to perform the stream transform.
                var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;

        }


        [RequiredAuthentication]
        public ActionResult RedirectToHome()
        {
            try
            {
                Login login = new Login();
                string actionToRedirect = login.GetHomePageAction();

                ////Insert Log
                login.InsertLogDetails();

                //changes by koustubh nakate on 19/08/2013 for role wise home screen

                int roleCode = PMGSYSession.Current.RoleCode;

                if (PMGSYSession.Current.RoleCode == 21 || PMGSYSession.Current.RoleCode == 33 || PMGSYSession.Current.RoleCode == 26 || PMGSYSession.Current.RoleCode == 66)
                {
                    TempData["roleDefaultPage"] = actionToRedirect;
                    return Redirect("~/Accounts/AccountDashBoard");
                }
                else if (roleCode == 46 || roleCode == 10)  //role code 36(itno) replaced by 46(Finance) 
                {
                    return RedirectToAction("FundTypeSelection", "Accounts");
                }
                else if (roleCode == 74)
                {

                    return RedirectToAction("GetRegisterGrievanceLayout", "ContractorGrievances", new { area = "ContractorGrievances" });
                }


                else
                {
                    return Redirect(actionToRedirect);
                }
            }
            catch (Exception ex)
            {
                Elmah.ErrorSignal.FromCurrentContext().Raise(ex, HttpContext.ApplicationInstance.Context);
                return Redirect("/Login/SessionExpire");
            }
        }


        public ActionResult GetCaptchaImages()
        {
            return CaptchaLib.ControllerExtensions.Captcha(this);
        }


        //code added by Vikram (suggested by Anita Mam) for regenerating ASPNet_SessionId
        void regenerateId()
        {

            System.Web.SessionState.SessionIDManager manager = new System.Web.SessionState.SessionIDManager();

            string oldId = manager.GetSessionID(System.Web.HttpContext.Current);

            string newId = manager.CreateSessionID(System.Web.HttpContext.Current);

            bool isAdd = false, isRedir = false;

            manager.SaveSessionID(System.Web.HttpContext.Current, newId, out isRedir, out isAdd);

            HttpApplication ctx = (HttpApplication)System.Web.HttpContext.Current.ApplicationInstance;

            HttpModuleCollection mods = ctx.Modules;

            System.Web.SessionState.SessionStateModule ssm = (System.Web.SessionState.SessionStateModule)mods.Get("Session");

            System.Reflection.FieldInfo[] fields = ssm.GetType().GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            System.Web.SessionState.SessionStateStoreProviderBase store = null;

            System.Reflection.FieldInfo rqIdField = null, rqLockIdField = null, rqStateNotFoundField = null;

            foreach (System.Reflection.FieldInfo field in fields)
            {

                if (field.Name.Equals("_store")) store = (System.Web.SessionState.SessionStateStoreProviderBase)field.GetValue(ssm);

                if (field.Name.Equals("_rqId")) rqIdField = field;

                if (field.Name.Equals("_rqLockId")) rqLockIdField = field;

                if (field.Name.Equals("_rqSessionStateNotFound")) rqStateNotFoundField = field;

            }

            object lockId = rqLockIdField.GetValue(ssm);

            if ((lockId != null) && (oldId != null)) store.ReleaseItemExclusive(System.Web.HttpContext.Current, oldId, lockId);

            rqStateNotFoundField.SetValue(ssm, true);

            rqIdField.SetValue(ssm, newId);

            Session["ASP.NET_SessionId"] = newId;



        }


        //#region Menu Render PMGSY3
        //[Audit]
        //public ActionResult MenuSelection()
        //{
        //    SchemewiseMenuSelectionViewModel model = new SchemewiseMenuSelectionViewModel();
        //    try
        //    {
        //        ViewBag.EncryptedProgramme = URLEncrypt.EncryptParameters(new string[] { "P" });
        //        model.lstPmgsyScheme = new List<SelectListItem>();
        //        model.lstPmgsyScheme.Insert(0, new SelectListItem() { Text = "PMGSY-1", Value = "1" });
        //        model.lstPmgsyScheme.Insert(1, new SelectListItem() { Text = "PMGSY-2", Value = "2" });
        //        model.lstPmgsyScheme.Insert(2, new SelectListItem() { Text = "RCPLWE", Value = "3" });
        //        model.lstPmgsyScheme.Insert(3, new SelectListItem() { Text = "PMGSY-3", Value = "4" });

        //        return View(model);
        //    }
        //    catch (Exception ex)
        //    {
        //        ErrorLog.LogError(ex, "Login.MenuSelection()");
        //        return null;
        //    }
        //}

        //[Audit]
        //public ActionResult SetRedirectUrl(string id)
        //{
        //    try
        //    {
        //        //string[] strParameters = URLEncrypt.DecryptParameters(new string[] { parameter, hash, key });
        //        PMGSYSession.Current.PMGSYScheme = Convert.ToByte(id.Trim());
        //        int roleCode = PMGSYSession.Current.RoleCode;
        //        string url = string.Empty;

        //        if (roleCode == 22)
        //        {
        //            url = PMGSYSession.Current.PMGSYScheme == 4 ? "/ExistingRoads/ListExistingRoadsPMGSY3" : PMGSYSession.Current.PMGSYScheme == 3 ? "/ExistingRoads/ListExistingRoads" : "/Proposal/ListProposal";
        //        }
        //        else if (roleCode == 36)
        //        {
        //            url = PMGSYSession.Current.PMGSYScheme == 4 ? "/ExistingRoads/GetTraceMaps" : "/LocationMasterDataEntry/MasterDataEntry";
        //        }
        //        else if (roleCode == 2)
        //        {
        //            url = PMGSYSession.Current.PMGSYScheme == 4 ? "/ExistingRoads/GetTraceMaps" : "/Proposal/ListProposal";
        //        }
        //        else if (roleCode == 3)
        //        {
        //            url = PMGSYSession.Current.PMGSYScheme == 4 ? "/Proposal/ListProposalPMGSY3" : "/Proposal/ListProposal";
        //        }

        //        return Json(new { status = true, url = url }, JsonRequestBehavior.AllowGet);
        //    }
        //    catch (Exception ex)
        //    {
        //        ErrorLog.LogError(ex, "Login.SetRedirectUrl()");
        //        return Redirect("login/error");
        //    }
        //}
        //#endregion

    }
}