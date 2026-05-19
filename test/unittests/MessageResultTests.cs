using NUnit.Framework;
using OAuth2NetCore;

namespace UnitTests
{
    [TestFixture]
    public class MessageResultTests
    {
        [Test]
        public void DefaultMsgCode_IsSuccess_True()
        {
            var mr = new MessageResult<string>();

            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Msg_Success));
            Assert.That(mr.IsSuccess, Is.True);
        }

        [Test]
        public void NonSuccessMsgCode_IsSuccess_False()
        {
            var mr = new MessageResult<string> { MsgCode = OAuth2Consts.Err_invalid_client };

            Assert.That(mr.IsSuccess, Is.False);
        }

        [Test]
        public void Result_RoundTrips()
        {
            var mr = new MessageResult<int> { Result = 42 };

            Assert.That(mr.Result, Is.EqualTo(42));
            Assert.That(mr.IsSuccess, Is.True);
        }
    }
}
