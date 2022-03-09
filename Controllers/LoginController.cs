using EFORM.DAL;
using EFORM.Extensions;
using EFORM.Models;
using System;
using System.Collections.Generic;
using System.Linq;
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
       
    }
}