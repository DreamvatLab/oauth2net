namespace OAuth2NetCore {
    public class MessageResult<T>
    {
        public string MsgCode { get; set; } = OAuth2Consts.Msg_Success;
        public string MsgCodeDescription { get; set; }
        public T Result { get; set; }

        public bool IsSuccess => MsgCode == OAuth2Consts.Msg_Success;
    }
}