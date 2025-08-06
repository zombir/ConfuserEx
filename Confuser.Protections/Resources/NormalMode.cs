using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Confuser.Protections.Resources {
	internal class NormalMode : IEncodeMode {
		public IEnumerable<Instruction> EmitDecrypt(MethodDef init, REContext ctx, Local block, Local key) {
			for (int i = 0; i < 0x10; i++) {
				if (ctx.Random.NextBoolean()) {
					// 插入死代码指令（不会影响功能）
					yield return Instruction.Create(OpCodes.Nop);
					yield return Instruction.Create(OpCodes.Ldc_I4_0);
					yield return Instruction.Create(OpCodes.Pop);
				}

				yield return Instruction.Create(OpCodes.Ldloc, block);
				yield return Instruction.Create(OpCodes.Ldc_I4, i);

				if (ctx.Random.NextBoolean()) {
					// 插入无害冗余指令
					yield return Instruction.Create(OpCodes.Ldloc, block);
					yield return Instruction.Create(OpCodes.Pop);
				}

				yield return Instruction.Create(OpCodes.Ldloc, block);
				yield return Instruction.Create(OpCodes.Ldc_I4, i);
				yield return Instruction.Create(OpCodes.Ldelem_U4);

				if (ctx.Random.NextBoolean()) {
					// 插入无害冗余指令
					yield return Instruction.Create(OpCodes.Ldloc, block);
					yield return Instruction.Create(OpCodes.Pop);
				}

				yield return Instruction.Create(OpCodes.Ldloc, key);
				yield return Instruction.Create(OpCodes.Ldc_I4, i);
				yield return Instruction.Create(OpCodes.Ldelem_U4);
				yield return Instruction.Create(OpCodes.Ldc_I4, 5);
				yield return Instruction.Create(OpCodes.Shl);

				if (ctx.Random.NextBoolean()) {
					// 可插入更多混淆指令
					yield return Instruction.Create(OpCodes.Dup);
					yield return Instruction.Create(OpCodes.Pop);
				}

				yield return Instruction.Create(OpCodes.Ldloc, key);
				yield return Instruction.Create(OpCodes.Ldc_I4, i);
				yield return Instruction.Create(OpCodes.Ldelem_U4);
				yield return Instruction.Create(OpCodes.Ldc_I4, 27);
				yield return Instruction.Create(OpCodes.Shr_Un);

				if (ctx.Random.NextBoolean()) {
					// 插入无害冗余指令
					yield return Instruction.Create(OpCodes.Ldloc, block);
					yield return Instruction.Create(OpCodes.Pop);
				}

				yield return Instruction.Create(OpCodes.Or);      // (k << 5) | (k >> 27)
				yield return Instruction.Create(OpCodes.Xor);     // block ^ 上面结果

				yield return Instruction.Create(OpCodes.Ldloc, key);
				yield return Instruction.Create(OpCodes.Ldc_I4, i);
				yield return Instruction.Create(OpCodes.Ldelem_U4);
				yield return Instruction.Create(OpCodes.Ldc_I4, 3);
				yield return Instruction.Create(OpCodes.Shr_Un);  // k >> 3

				yield return Instruction.Create(OpCodes.Sub);      // - (k >> 3)

				if (ctx.Random.NextBoolean()) {
					// 插入死代码指令（不会影响功能）
					yield return Instruction.Create(OpCodes.Nop);
					yield return Instruction.Create(OpCodes.Ldc_I4_0);
					yield return Instruction.Create(OpCodes.Pop);
				}

				yield return Instruction.Create(OpCodes.Ldloc, key);
				yield return Instruction.Create(OpCodes.Ldc_I4, i);
				yield return Instruction.Create(OpCodes.Ldelem_U4);
				yield return Instruction.Create(OpCodes.Xor);      // ^ k

				yield return Instruction.Create(OpCodes.Stelem_I4);
			}
		}

		public uint[] Encrypt(uint[] data, int offset, uint[] key) {
			var ret = new uint[key.Length];
			for (int i = 0; i < key.Length; i++) {
				uint v = data[i + offset];
				uint k = key[i];
				// 变形加密：先异或，再加，最后左移扰乱
				ret[i] = ((v ^ k) + (k >> 3)) ^ ((k << 5) | (k >> 27));
			}
			return ret;
		}
	}
}
