//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace EFORM.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class UM_User_Master
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public UM_User_Master()
        {
            this.ADMIN_DEPARTMENT = new HashSet<ADMIN_DEPARTMENT>();
            this.EFORM_MASTER = new HashSet<EFORM_MASTER>();
            this.EFORM_MASTER1 = new HashSet<EFORM_MASTER>();
            this.EFORM_MASTER2 = new HashSet<EFORM_MASTER>();
            this.EFORM_PIU_GENERAL_INFO = new HashSet<EFORM_PIU_GENERAL_INFO>();
            this.EFORM_PIU_MIX_DESIGN_DETAILS = new HashSet<EFORM_PIU_MIX_DESIGN_DETAILS>();
            this.EFORM_PIU_PREVIOUS_INSP_DETAILS = new HashSet<EFORM_PIU_PREVIOUS_INSP_DETAILS>();
            this.EFORM_PIU_PRGS_DETAILS = new HashSet<EFORM_PIU_PRGS_DETAILS>();
            this.EFORM_PIU_QC__DETAILS = new HashSet<EFORM_PIU_QC__DETAILS>();
            this.EFORM_QM_ARRANGEMENTS_OBS_DETAILS = new HashSet<EFORM_QM_ARRANGEMENTS_OBS_DETAILS>();
            this.EFORM_QM_GEOMETRICS_DETAILS = new HashSet<EFORM_QM_GEOMETRICS_DETAILS>();
            this.EFORM_QM_PRESENT_WORK_DETAILS = new HashSet<EFORM_QM_PRESENT_WORK_DETAILS>();
            this.EFORM_QM_QUALITY_ATTENTION = new HashSet<EFORM_QM_QUALITY_ATTENTION>();
            this.EXEC_LSB_MONTHLY_STATUS = new HashSet<EXEC_LSB_MONTHLY_STATUS>();
            this.EXEC_ROADS_MONTHLY_STATUS = new HashSet<EXEC_ROADS_MONTHLY_STATUS>();
            this.MASTER_BLOCK = new HashSet<MASTER_BLOCK>();
            this.MASTER_DISTRICT = new HashSet<MASTER_DISTRICT>();
            this.MASTER_STATE = new HashSet<MASTER_STATE>();
            this.UM_User_Log = new HashSet<UM_User_Log>();
            this.UM_User_Profile = new HashSet<UM_User_Profile>();
            this.UM_User_Role_Mapping = new HashSet<UM_User_Role_Mapping>();
            this.CONTRACTOR_REGISTRATION_DETAILS = new HashSet<CONTRACTOR_REGISTRATION_DETAILS>();
            this.MASTER_AGENCY = new HashSet<MASTER_AGENCY>();
        }
    
        public int UserID { get; set; }
        public string UserName { get; set; }
        public short LevelID { get; set; }
        public short DefaultRoleID { get; set; }
        public Nullable<int> Mast_State_Code { get; set; }
        public Nullable<int> Mast_District_Code { get; set; }
        public Nullable<int> Admin_ND_Code { get; set; }
        public string Password { get; set; }
        public Nullable<int> FailedPasswordAttempts { get; set; }
        public Nullable<int> FailedPasswordAnswerAttempts { get; set; }
        public Nullable<System.DateTime> LastPasswordChangedDate { get; set; }
        public Nullable<System.DateTime> LastLoginDate { get; set; }
        public short PreferedLanguageID { get; set; }
        public short PreferedCssID { get; set; }
        public bool IsFirstLogin { get; set; }
        public bool IsLocked { get; set; }
        public bool IsActive { get; set; }
        public short ConcurrentLoginCount { get; set; }
        public Nullable<short> MaxConcurrentLoginsAllowed { get; set; }
        public System.DateTime CreationDate { get; set; }
        public string Remarks { get; set; }
        public int CreatedBy { get; set; }
    
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<ADMIN_DEPARTMENT> ADMIN_DEPARTMENT { get; set; }
        public virtual ADMIN_DEPARTMENT ADMIN_DEPARTMENT1 { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_MASTER> EFORM_MASTER { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_MASTER> EFORM_MASTER1 { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_MASTER> EFORM_MASTER2 { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_GENERAL_INFO> EFORM_PIU_GENERAL_INFO { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_MIX_DESIGN_DETAILS> EFORM_PIU_MIX_DESIGN_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_PREVIOUS_INSP_DETAILS> EFORM_PIU_PREVIOUS_INSP_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_PRGS_DETAILS> EFORM_PIU_PRGS_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_PIU_QC__DETAILS> EFORM_PIU_QC__DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_ARRANGEMENTS_OBS_DETAILS> EFORM_QM_ARRANGEMENTS_OBS_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_GEOMETRICS_DETAILS> EFORM_QM_GEOMETRICS_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_PRESENT_WORK_DETAILS> EFORM_QM_PRESENT_WORK_DETAILS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EFORM_QM_QUALITY_ATTENTION> EFORM_QM_QUALITY_ATTENTION { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EXEC_LSB_MONTHLY_STATUS> EXEC_LSB_MONTHLY_STATUS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<EXEC_ROADS_MONTHLY_STATUS> EXEC_ROADS_MONTHLY_STATUS { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MASTER_BLOCK> MASTER_BLOCK { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MASTER_DISTRICT> MASTER_DISTRICT { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MASTER_STATE> MASTER_STATE { get; set; }
        public virtual MASTER_STATE MASTER_STATE1 { get; set; }
        public virtual UM_Level_Master UM_Level_Master { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UM_User_Log> UM_User_Log { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UM_User_Profile> UM_User_Profile { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<UM_User_Role_Mapping> UM_User_Role_Mapping { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<CONTRACTOR_REGISTRATION_DETAILS> CONTRACTOR_REGISTRATION_DETAILS { get; set; }
        public virtual UM_Css_Master UM_Css_Master { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<MASTER_AGENCY> MASTER_AGENCY { get; set; }
    }
}